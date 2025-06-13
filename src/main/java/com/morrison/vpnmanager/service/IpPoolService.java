package com.morrison.vpnmanager.service;


import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class IpPoolService {

    private final Queue<String> availableIps = new LinkedList<>();
    private final Set<String> allocatedIps = new HashSet<>();

    public IpPoolService() {
        initialAvailableIps();

    }

    public synchronized String allocateIp() {
        String ip = availableIps.poll();
        if (ip != null) {
            allocatedIps.add(ip);
        }
        return ip;
    }

    public synchronized void releaseIp(String ip) {
        if (allocatedIps.remove(ip)) {
            availableIps.add(ip);
        }
    }

    public synchronized void resetIpPool() {
        availableIps.clear();
        allocatedIps.clear();
        initialAvailableIps();
    }

    private void initialAvailableIps() {
        int start = 10;
        int end = 254;
        for (int i = start; i <= end; i++) {
            String subnet = "10.0.0.";
            availableIps.add(subnet + i);
        }
    }

    public String getSubnet() {
        return "/24";
    }

    public List<String> getAllocatedIps() {
        return new ArrayList<>(allocatedIps);
    }

    public List<String> getAvailableIps() {
        return new ArrayList<>(availableIps);
    }
}
