package com.morrison.vpnmanager.dto.response;

public record WireguardClientResponse(WireguardClientCredentials credentials, Integer wireguardClientExpireJobId) {

}
