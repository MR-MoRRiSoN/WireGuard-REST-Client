package com.morrison.vpnmanager.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class WireGuardPeer {
    // Getters and setters
    private String publicKey;
    private String endpoint;
    private String allowedIPs;
    private String latestHandshake;
    private String transfer;
    private boolean connected;

    @Override
    public String toString() {
        return String.format("WireGuardPeer{publicKey='%s', endpoint='%s', allowedIPs='%s', latestHandshake='%s', connected=%s, transfer='%s'}",
                publicKey, endpoint, allowedIPs, latestHandshake, connected, transfer);
    }
}
