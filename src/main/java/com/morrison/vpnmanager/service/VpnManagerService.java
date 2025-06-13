package com.morrison.vpnmanager.service;

import com.morrison.vpnmanager.dto.*;
import com.morrison.vpnmanager.dto.request.UpdateWireguardClient;
import com.morrison.vpnmanager.dto.response.*;
import com.morrison.vpnmanager.enums.VpnStatuses;
import com.morrison.vpnmanager.enums.WireguardClientConnectionStatus;
import com.morrison.vpnmanager.exception.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class VpnManagerService {

    // Constants
    private static final String WG_INTERFACE = "wg0";
    private static final int COMMAND_TIMEOUT_SECONDS = 30;
    private static final int CONNECTION_TIMEOUT_SECONDS = 120;
    private static final double BYTES_TO_MB = 1024.0 * 1024.0;
    private static final String SUDO_FLAG = "-S";
    private static final Pattern JOB_ID_PATTERN = Pattern.compile("job (\\d+) at");
    private static final DateTimeFormatter SCHEDULER_TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm MM/dd/yy");

    // Configuration
    @Value("${ubuntu.sudo.password}")
    private String sudoPassword;

    // Dependencies
    private final IpPoolService ipPoolService;

    /**
     * Retrieves VPN server configuration including keys, port, and external IP
     */
    public WireGuardSimpleDataResponse getVpnServerKeys() {
        log.info("Retrieving VPN server configuration");

        CompletableFuture<String> publicKeyFuture = executeCommandAsync(new String[]{"sudo", "wg", "show", WG_INTERFACE, "public-key"});
        CompletableFuture<String> privateKeyFuture = executeCommandAsync(new String[]{"sudo", "wg", "show", WG_INTERFACE, "private-key"});
        CompletableFuture<String> portFuture = executeCommandAsync(new String[]{"sudo", "wg", "show", WG_INTERFACE, "listen-port"});
        CompletableFuture<String> externalIpFuture = executeCommandAsync(new String[]{"curl", "-s", "https://api.ipify.org"});

        String publicKey = publicKeyFuture.join().trim();
        String privateKey = privateKeyFuture.join().trim();
        String port = portFuture.join().trim();
        String externalIp = externalIpFuture.join().trim();

        return new WireGuardSimpleDataResponse(publicKey, privateKey, externalIp, Integer.parseInt(port));
    }

    /**
     * Retrieves connection data for multiple Wireguard clients
     */

    public List<WireguardClientConnectionDataResponse> getWireguardClientConnectionListData(List<String> clientPublicKeys) throws IOException, InterruptedException {
        validateClientPublicKeys(clientPublicKeys);
        List<WireguardClientConnectionDataResponse> responseList = new ArrayList<>();
        for (String clientPublicKey : clientPublicKeys) {
            responseList.add(getWireguardClientConnectionData(clientPublicKey));

        }
        return responseList;
    }

    /**
     * Retrieves connection data for a specific Wireguard client
     */
    public WireguardClientConnectionDataResponse getWireguardClientConnectionData(String clientPublicKey) throws IOException, InterruptedException {
        validatePublicKey(clientPublicKey);

        String[] command = {"sudo", SUDO_FLAG, "wg", "show", WG_INTERFACE, "dump"};
        CommandResult result = executeCommandWithPassword(command);

        if (result.exitCode() != 0) {
            log.warn("Failed to execute wg show dump command: {}", result.errorOutput());
            return createExpiredConnectionResponse(clientPublicKey);
        }

        return parseClientConnectionData(result.output(), clientPublicKey);
    }

    private WireguardClientConnectionDataResponse createExpiredConnectionResponse(String publicKey) {
        return new WireguardClientConnectionDataResponse(WireguardClientConnectionStatus.EXPIRED, null, null, publicKey);
    }

    /**
     * Starts the WireGuard interface
     */
    public VpnStatusResponse startWireGuard() throws IOException, InterruptedException {
        log.info("Starting WireGuard interface: {}", WG_INTERFACE);

        String[] startCommand = {"sudo", SUDO_FLAG, "wg-quick", "up", WG_INTERFACE};
        CommandResult result = executeCommandWithPassword(startCommand);

        if (result.exitCode() == 0) {
            ipPoolService.resetIpPool();
            log.info("WireGuard started successfully");
            return new VpnStatusResponse(VpnStatuses.STARTED, "WireGuard started successfully");
        }

        String errorMessage = String.format("WireGuard start failed with exit code %d: %s", result.exitCode(), result.errorOutput());
        log.error(errorMessage);
        throw new WireguardStartException(errorMessage);
    }

    /**
     * Stops the WireGuard interface
     */
    public VpnStatusResponse stopWireGuard() throws IOException, InterruptedException {
        log.info("Stopping WireGuard interface: {}", WG_INTERFACE);

        String[] stopCommand = {"sudo", SUDO_FLAG, "wg-quick", "down", WG_INTERFACE};
        CommandResult result = executeCommandWithPassword(stopCommand);

        if (result.exitCode() == 0) {
            log.info("WireGuard stopped successfully");
            return new VpnStatusResponse(VpnStatuses.STOPPED, "WireGuard stopped successfully");
        }

        String errorMessage = String.format("WireGuard stop failed with exit code %d: %s", result.exitCode(), result.errorOutput());
        log.error(errorMessage);
        throw new WireguardStopException(errorMessage);
    }

    /**
     * Checks if WireGuard interface is running
     */
    public VpnStatusResponse isWireGuardRunning() throws IOException, InterruptedException {
        String[] statusCommand = {"sudo", SUDO_FLAG, "wg", "show", WG_INTERFACE};
        CommandResult result = executeCommandWithPassword(statusCommand);

        VpnStatuses status = result.exitCode() == 0 ? VpnStatuses.STARTED : VpnStatuses.STOPPED;
        String message = String.format("WireGuard status is %s", status);

        return new VpnStatusResponse(status, message);
    }

    /**
     * Lists all configured clients (peers)
     */
    public List<WireGuardPeer> listAllClients() throws IOException, InterruptedException {
        String[] listCommand = {"sudo", SUDO_FLAG, "wg", "show", WG_INTERFACE, "peers"};
        CommandResult result = executeCommandWithPassword(listCommand);

        if (result.exitCode() != 0) {
            log.warn("Failed to list peers: {}", result.errorOutput());
            return new ArrayList<>();
        }

        return parsePeerKeys(result.output());
    }

    /**
     * Lists currently connected clients
     */
    public List<WireGuardPeer> listConnectedClients() throws IOException, InterruptedException {
        return getDetailedPeerInfo(true);
    }

    /**
     * Gets detailed information about all peers
     */
    public List<WireGuardPeer> getDetailedPeerInfo() throws IOException, InterruptedException {
        return getDetailedPeerInfo(false);
    }

    /**
     * Deletes all scheduled tasks
     */
    public boolean deleteAllTimeSchedule() throws IOException, InterruptedException {
        String shellCommand = "atq | awk '{print $1}' | xargs -r sudo atrm";
        String[] command = {"sudo", SUDO_FLAG, "sh", "-c", shellCommand};
        CommandResult result = executeCommandWithPassword(command);
        return result.exitCode() == 0;
    }

    /**
     * Creates a Wireguard client with scheduled removal
     */
    public WireguardClientResponse createWireguardClientWithEndTime(LocalDateTime endTime) throws IOException, InterruptedException {
        validateEndTime(endTime);

        WireguardClientCredentials credentials = createWireguardClient();
        if (credentials == null) {
            throw new ClientCreationException("Failed to create Wireguard client credentials");
        }

        Integer schedulerJobId = scheduleWireguardClientRemoval(endTime, credentials.clientPublicKey());
        return new WireguardClientResponse(credentials, schedulerJobId);
    }

    /**
     * Updates a Wireguard client's scheduled removal time
     */
    public UpdateWireguardClientResponse updateWireguardClientWithEndTime(UpdateWireguardClient updateRequest) throws IOException, InterruptedException {
        validateUpdateRequest(updateRequest);
        Integer newTaskId = null;
        try {
            deleteSchedulerTask(updateRequest.getSchedulerJobId());
            newTaskId = scheduleWireguardClientRemoval(updateRequest.getSchedulerEndTime(), updateRequest.getPublicKey());
        } catch (Exception e) {
            CommandResult result = createWireguardPeer(updateRequest.getPublicKey(), updateRequest.getClientIp());
            if (result.exitCode() == 0) {
                newTaskId = scheduleWireguardClientRemoval(updateRequest.getSchedulerEndTime(), updateRequest.getPublicKey());
            }
        }
        return new UpdateWireguardClientResponse(updateRequest.getPublicKey(), newTaskId);
    }

    public Integer getActiveClientsCount() throws IOException, InterruptedException {
        log.info("Retrieving count of active WireGuard clients");

        try {
            List<WireGuardPeer> connectedClients = listConnectedClients();
            int activeCount = connectedClients.size();

            log.info("Found {} active WireGuard clients", activeCount);
            return activeCount;

        } catch (Exception e) {
            log.error("Failed to retrieve active clients count: {}", e.getMessage());
            throw e;
        }
    }

    public void terminateVpnClientSession(DeleteWireguardClient wireguardClient) throws IOException, InterruptedException {
        deleteSchedulerTask(wireguardClient.getSchedulerJobId());
        removeWireguardPeer(wireguardClient.getPublicKey());
    }

    /**
     * Removes a WireGuard peer by public key
     */
    private void removeWireguardPeer(String publicKey) throws IOException, InterruptedException {
        log.info("Removing WireGuard peer with public key: {}", publicKey);

        String[] command = {"sudo", SUDO_FLAG, "wg", "set", WG_INTERFACE, "peer", publicKey, "remove"};
        CommandResult result = executeCommandWithPassword(command);

        if (result.exitCode() != 0) {
            String errorMessage = String.format("Failed to remove WireGuard peer %s: %s", publicKey, result.errorOutput());
            log.error(errorMessage);
            throw new ClientDeletionException(errorMessage);
        }

        log.info("Successfully removed WireGuard peer: {}", publicKey);
    }

    /**
     * Creates a new Wireguard client
     */
    public WireguardClientCredentials createWireguardClient() throws IOException, InterruptedException {
        WireGuardKey keyPair = generateWireguardKeyPair();
        String clientIp = ipPoolService.allocateIp();

        validateAllocatedIp(clientIp);

        CommandResult result = createWireguardPeer(keyPair.publicKeyBase64(), clientIp);

        if (result.exitCode() == 0) {
            log.info("Successfully created Wireguard client with IP: {}", clientIp);
            return new WireguardClientCredentials(clientIp, keyPair.publicKeyBase64(), keyPair.privateKeyBase64());
        }

        log.error("WireGuard peer creation failed: {}", result.errorOutput());
        ipPoolService.releaseIp(clientIp);
        throw new ClientCreationException("Failed to create Wireguard peer: " + result.errorOutput());
    }

    private CommandResult createWireguardPeer(String publicKey, String clientIp) throws IOException, InterruptedException {
        String[] command = {"sudo", SUDO_FLAG, "wg", "set", WG_INTERFACE, "peer", publicKey, "allowed-ips", clientIp};
        return executeCommandWithPassword(command);
    }

    // Private helper methods

    private CompletableFuture<String> executeCommandAsync(String[] command) {
        return CompletableFuture.supplyAsync(() -> {
            CommandResult result;
            try {
                result = executeCommandWithPassword(command);
            } catch (IOException | InterruptedException e) {
                throw new RuntimeException(e);
            }
            if (result.exitCode() != 0) {
                throw new CommandExecutionException("Command failed: " + result.errorOutput());
            }
            return result.output();
        });
    }


    private WireguardClientConnectionDataResponse parseClientConnectionData(String output, String clientPublicKey) {
        String[] lines = output.split("\n");

        for (String line : lines) {
            if (line.contains(clientPublicKey)) {
                String[] parts = line.split("\\t");
                if (parts.length >= 8) {
                    return createConnectionDataFromParts(parts, clientPublicKey);
                }
            }
        }

        return createExpiredConnectionResponse(clientPublicKey);
    }

    private WireguardClientConnectionDataResponse createConnectionDataFromParts(String[] parts, String publicKey) {
        long latestHandshake = Long.parseLong(parts[4]);
        long transferRx = Long.parseLong(parts[5]);
        long transferTx = Long.parseLong(parts[6]);

        long currentEpoch = System.currentTimeMillis() / 1000;
        boolean isConnected = (currentEpoch - latestHandshake) <= CONNECTION_TIMEOUT_SECONDS;

        WireguardClientConnectionStatus status = isConnected ? WireguardClientConnectionStatus.CONNECTED : WireguardClientConnectionStatus.DISCONNECTED;

        Long connectionDuration = isConnected ? currentEpoch - latestHandshake : null;
        double transferredMB = (transferRx + transferTx) / BYTES_TO_MB;

        return new WireguardClientConnectionDataResponse(status, connectionDuration, transferredMB, publicKey);
    }

    private List<WireGuardPeer> parsePeerKeys(String output) throws IOException, InterruptedException {
        if (!StringUtils.hasText(output)) {
            return new ArrayList<>();
        }

        String[] peerKeys = output.trim().split("\n");
        List<WireGuardPeer> peers = new ArrayList<>();

        for (String peerKey : peerKeys) {
            if (StringUtils.hasText(peerKey.trim())) {
                Optional<WireGuardPeer> peer = getPeerDetails(peerKey.trim());
                peer.ifPresent(peers::add);
            }
        }

        return peers;
    }

    private List<WireGuardPeer> getDetailedPeerInfo(boolean onlyConnected) throws IOException, InterruptedException {
        String[] showCommand = {"sudo", SUDO_FLAG, "wg", "show", WG_INTERFACE};
        CommandResult result = executeCommandWithPassword(showCommand);

        if (result.exitCode() == 0) {
            return parseWireGuardOutput(result.output(), onlyConnected);
        }

        return new ArrayList<>();
    }

    private void deleteSchedulerTask(Integer jobId) throws IOException, InterruptedException {
        if (jobId == null) {
            return;
        }

        String[] command = {"sudo", SUDO_FLAG, "sh", "-c", "atrm " + jobId};
        CommandResult result = executeCommandWithPassword(command);

        if (StringUtils.hasText(result.errorOutput())) {
            log.warn("Failed to delete job ID {}. Error: {}", jobId, result.errorOutput());
            throw new SchedulerException("Failed to delete scheduler task with job ID: " + jobId);
        }

        log.info("Successfully deleted scheduler task with job ID: {}", jobId);
    }

    private Integer scheduleWireguardClientRemoval(LocalDateTime endTime, String publicKey) throws IOException, InterruptedException {
        String removalCommand = String.format("sudo wg set %s peer %s remove", WG_INTERFACE, publicKey);
        String formattedTime = endTime.format(SCHEDULER_TIME_FORMAT);

        log.info("Scheduling removal command at: {}", formattedTime);

        String[] command = {"sudo", SUDO_FLAG, "sh", "-c", "echo '" + removalCommand + "' | at " + formattedTime};

        CommandResult result = executeCommandWithPassword(command);
        String output = result.output() + result.errorOutput();

        return extractJobId(output);
    }

    private Integer extractJobId(String output) {
        Matcher matcher = JOB_ID_PATTERN.matcher(output);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }

        log.warn("Job scheduling failed or job ID not found. Output: {}", output);
        throw new SchedulerException("Job scheduling failed or job ID not found");
    }

    private Optional<WireGuardPeer> getPeerDetails(String publicKey) throws IOException, InterruptedException {
        String[] detailCommand = {"sudo", SUDO_FLAG, "wg", "show", WG_INTERFACE, "dump"};
        CommandResult result = executeCommandWithPassword(detailCommand);

        if (result.exitCode() == 0) {
            String[] lines = result.output().split("\n");
            for (String line : lines) {
                if (line.contains(publicKey)) {
                    return Optional.ofNullable(parsePeerLine(line));
                }
            }
        }

        return Optional.empty();
    }

    private CommandResult executeCommandWithPassword(String[] command) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(false);

        Process process = startProcess(pb);
        providePasswordIfNeeded(process);

        StringBuilder output = new StringBuilder();
        StringBuilder errorOutput = new StringBuilder();

        readProcessStreams(process, output, errorOutput);

        boolean finished = waitForProcess(process);
        if (!finished) {
            process.destroyForcibly();
            throw new CommandTimeoutException("Command timed out after " + COMMAND_TIMEOUT_SECONDS + " seconds");
        }

        return new CommandResult(process.exitValue(), output.toString(), errorOutput.toString());
    }

    private Process startProcess(ProcessBuilder pb) throws IOException {
        return pb.start();
    }

    private void providePasswordIfNeeded(Process process) throws IOException {
        if (StringUtils.hasText(sudoPassword)) {
            OutputStreamWriter writer = new OutputStreamWriter(process.getOutputStream());
            writer.write(sudoPassword + "\n");
            writer.flush();
            writer.close();
        }
    }

    private void readProcessStreams(Process process, StringBuilder output, StringBuilder errorOutput) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }

        while ((line = errorReader.readLine()) != null) {
            errorOutput.append(line).append("\n");
        }

        reader.close();
        errorReader.close();
    }

    private boolean waitForProcess(Process process) throws InterruptedException {
        return process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    private List<WireGuardPeer> parseWireGuardOutput(String output, boolean onlyConnected) {
        List<WireGuardPeer> peers = new ArrayList<>();
        String[] lines = output.split("\n");

        WireGuardPeer currentPeer = null;

        for (String line : lines) {
            line = line.trim();

            if (line.startsWith("peer:")) {
                if (currentPeer != null && (!onlyConnected || currentPeer.isConnected())) {
                    peers.add(currentPeer);
                }
                currentPeer = createNewPeer(line);
            } else if (currentPeer != null) {
                updatePeerFromLine(currentPeer, line);
            }
        }

        if (currentPeer != null && (!onlyConnected || currentPeer.isConnected())) {
            peers.add(currentPeer);
        }

        return peers;
    }

    private WireGuardPeer createNewPeer(String line) {
        WireGuardPeer peer = new WireGuardPeer();
        peer.setPublicKey(line.substring(5).trim());
        return peer;
    }

    private void updatePeerFromLine(WireGuardPeer peer, String line) {
        if (line.startsWith("endpoint:")) {
            peer.setEndpoint(line.substring(9).trim());
        } else if (line.startsWith("allowed ips:")) {
            peer.setAllowedIPs(line.substring(12).trim());
        } else if (line.startsWith("latest handshake:")) {
            String handshake = line.substring(17).trim();
            peer.setLatestHandshake(handshake);
            peer.setConnected(!"(never)".equals(handshake));
        } else if (line.startsWith("transfer:")) {
            peer.setTransfer(line.substring(9).trim());
        }
    }

    private WireGuardPeer parsePeerLine(String line) {
        String[] parts = line.split("\t");
        if (parts.length >= 5) {
            WireGuardPeer peer = new WireGuardPeer();
            peer.setPublicKey(parts[1]);
            peer.setAllowedIPs(parts[3]);
            peer.setEndpoint(parts[2]);
            peer.setLatestHandshake(parts[4]);
            peer.setConnected(!"0".equals(parts[4]));

            if (parts.length > 6) {
                peer.setTransfer(String.format("%s received, %s sent", parts[5], parts[6]));
            }

            return peer;
        }
        return null;
    }

    private WireGuardKey generateWireguardKeyPair() {
        SecureRandom random = new SecureRandom();
        X25519KeyPairGenerator keyPairGenerator = new X25519KeyPairGenerator();
        keyPairGenerator.init(new KeyGenerationParameters(random, 256));

        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        X25519PrivateKeyParameters privateKey = (X25519PrivateKeyParameters) keyPair.getPrivate();
        X25519PublicKeyParameters publicKey = (X25519PublicKeyParameters) keyPair.getPublic();

        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        return new WireGuardKey(publicKeyBase64, privateKeyBase64);
    }

    // Validation methods
    private void validateClientPublicKeys(List<String> clientPublicKeys) {
        if (clientPublicKeys == null || clientPublicKeys.isEmpty()) {
            throw new InvalidInputException("Client public keys list cannot be null or empty");
        }
    }

    private void validatePublicKey(String clientPublicKey) {
        if (!StringUtils.hasText(clientPublicKey)) {
            throw new InvalidInputException("Client public key cannot be null or empty");
        }
    }

    private void validateEndTime(LocalDateTime endTime) {
        if (endTime == null) {
            throw new InvalidInputException("End time cannot be null");
        }
        if (endTime.isBefore(LocalDateTime.now())) {
            throw new InvalidInputException("End time must be in the future");
        }
    }

    private void validateUpdateRequest(UpdateWireguardClient updateRequest) {
        if (updateRequest == null) {
            throw new InvalidInputException("Update request cannot be null");
        }
        if (!StringUtils.hasText(updateRequest.getPublicKey())) {
            throw new InvalidInputException("Public key cannot be null or empty");
        }
        if (updateRequest.getSchedulerEndTime() == null) {
            throw new InvalidInputException("Scheduler end time cannot be null");
        }
    }

    private void validateAllocatedIp(String clientIp) {
        if (!StringUtils.hasText(clientIp)) {
            throw new IpAllocationException("No available IP addresses in pool");
        }
    }


}