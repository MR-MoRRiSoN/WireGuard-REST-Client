package com.morrison.vpnmanager.dto.response;

public record UpdateWireguardClientResponse (String publicKey, Integer wireguardClientExpireJobId) {
}
