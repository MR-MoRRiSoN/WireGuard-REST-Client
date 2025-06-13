package com.morrison.vpnmanager.dto;

import com.morrison.vpnmanager.enums.WireguardClientConnectionStatus;

public record WireguardClientConnectionDataResponse(
        WireguardClientConnectionStatus connectionStatus,
        Long connectionDuration,
        Double dataTransferredMobs,
        String publicKey
) {
}
