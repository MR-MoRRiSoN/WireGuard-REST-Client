package com.morrison.vpnmanager.dto;

public record WireGuardKey(
        String publicKeyBase64,
        String privateKeyBase64
) {
}
