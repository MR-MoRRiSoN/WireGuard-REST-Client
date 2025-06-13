package com.morrison.vpnmanager.dto.response;


public record WireguardClientCredentials(String clientIp, String clientPublicKey, String clientPrivateKey) {
}
