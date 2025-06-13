package com.morrison.vpnmanager.dto;

public record WireGuardSimpleDataResponse(String publicKey, String privateKey, String outsideIp,
                                          Integer wireguardPort) {
}
