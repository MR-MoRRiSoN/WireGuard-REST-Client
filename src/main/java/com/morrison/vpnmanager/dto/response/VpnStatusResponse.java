package com.morrison.vpnmanager.dto.response;

import com.morrison.vpnmanager.enums.VpnStatuses;

public record VpnStatusResponse(VpnStatuses status, String message) {
}
