package com.morrison.vpnmanager.controller;

import com.morrison.vpnmanager.dto.WireGuardPeer;
import com.morrison.vpnmanager.dto.WireGuardSimpleDataResponse;
import com.morrison.vpnmanager.dto.WireguardClientConnectionDataResponse;
import com.morrison.vpnmanager.dto.request.UpdateWireguardClient;
import com.morrison.vpnmanager.dto.response.*;
import com.morrison.vpnmanager.enums.VpnStatuses;
import com.morrison.vpnmanager.service.VpnManagerService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/vpn")
@RequiredArgsConstructor
public class VpnController {

    private final VpnManagerService vpnManagerService;

    /**
     * Start WireGuard service
     */
    @PostMapping("/start")
    public ResponseEntity<VpnStatusResponse> startVpn() throws IOException, InterruptedException {
        log.info("Request to start WireGuard");
        return ResponseEntity.ok(vpnManagerService.startWireGuard());
    }

    /**
     * Stop WireGuard service
     */
    @PostMapping("/stop")
    public ResponseEntity<VpnStatusResponse> stopVpn() throws IOException, InterruptedException {
        log.info("Request to stop WireGuard");
        return ResponseEntity.ok(vpnManagerService.stopWireGuard());
    }

    /**
     * Get WireGuard status
     */
    @GetMapping("/status")
    public ResponseEntity<VpnStatusResponse> getVpnStatus() throws IOException, InterruptedException {
        log.info("Request to get WireGuard status");
        return ResponseEntity.ok(vpnManagerService.isWireGuardRunning());
    }

    /**
     * List all configured clients
     */
    @GetMapping("/clients")
    public ResponseEntity<List<WireGuardPeer>> listAllClients() throws IOException, InterruptedException {
        log.info("Request to list all clients");
        List<WireGuardPeer> clients = vpnManagerService.listAllClients();
        return ResponseEntity.ok(clients);
    }

    /**
     * List currently connected clients
     */
    @GetMapping("/clients/connected")
    public ResponseEntity<List<WireGuardPeer>> listConnectedClients() throws IOException, InterruptedException {
        log.info("Request to list connected clients");
        List<WireGuardPeer> connectedClients = vpnManagerService.listConnectedClients();
        return ResponseEntity.ok(connectedClients);
    }

    /**
     * Get detailed information about all peers
     */
    @GetMapping("/clients/detailed")
    public ResponseEntity<List<WireGuardPeer>> getDetailedClientInfo() throws IOException, InterruptedException {
        log.info("Request to get detailed client information");
        List<WireGuardPeer> peers = vpnManagerService.getDetailedPeerInfo();
        return ResponseEntity.ok(peers);
    }

    @GetMapping("/clients/active-clients-count")
    public ResponseEntity<Integer> getActiveClientsCount() throws IOException, InterruptedException {
        return ResponseEntity.ok(vpnManagerService.getActiveClientsCount());
    }

    /**
     * Get comprehensive VPN information
     */
    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> getVpnInfo() throws IOException, InterruptedException {
        log.info("Request to get comprehensive VPN information");

        boolean isRunning = vpnManagerService.isWireGuardRunning().status() == VpnStatuses.STARTED;
        List<WireGuardPeer> allClients = vpnManagerService.listAllClients();
        List<WireGuardPeer> connectedClients = vpnManagerService.listConnectedClients();

        Map<String, Object> response = new HashMap<>();
        response.put("running", isRunning);
        response.put("status", isRunning ? "running" : "stopped");
        response.put("totalClients", allClients.size());
        response.put("connectedClients", connectedClients.size());
        response.put("clients", allClients);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/create-client")
    public ResponseEntity<WireguardClientCredentials> createVpnClient() throws IOException, InterruptedException {
        return ResponseEntity.ok(vpnManagerService.createWireguardClient());
    }

    @GetMapping("/get-vpn-server-data")
    public ResponseEntity<WireGuardSimpleDataResponse> getVpnServerKeys() {
        return ResponseEntity.ok(vpnManagerService.getVpnServerKeys());
    }


    @PostMapping("/load-vpn-client-connection-list-data")
    public ResponseEntity<List<WireguardClientConnectionDataResponse>> getVpnClientConnectionData(
            @RequestBody List<String> clientPublicKey) throws IOException, InterruptedException {
        if (clientPublicKey == null || clientPublicKey.isEmpty() || clientPublicKey.stream().anyMatch(String::isBlank)) {
            return ResponseEntity.badRequest().body(null);
        }
        return ResponseEntity.ok(vpnManagerService.getWireguardClientConnectionListData(clientPublicKey));
    }

    @PutMapping("/update-vpn-client-limited-time")
    public ResponseEntity<UpdateWireguardClientResponse> updateWireguardLimitedTime(@RequestBody @Valid UpdateWireguardClient wireguardClient) throws IOException, InterruptedException {
        return ResponseEntity.ok(vpnManagerService.updateWireguardClientWithEndTime(wireguardClient));
    }

    @PostMapping("/terminate-vpn-client-session")
    public ResponseEntity<String> terminateVpnClientSession(@RequestBody @Valid DeleteWireguardClient wireguardClient) throws IOException, InterruptedException {
        vpnManagerService.terminateVpnClientSession(wireguardClient);
        return ResponseEntity.ok("success");
    }


    @PostMapping("/create-client-with-limited-time/{time}")
    public ResponseEntity<WireguardClientResponse> createWireguardClientWithLimitedTime(@PathVariable LocalDateTime time) throws IOException, InterruptedException {
        return ResponseEntity.ok(vpnManagerService.createWireguardClientWithEndTime(time));
    }
}