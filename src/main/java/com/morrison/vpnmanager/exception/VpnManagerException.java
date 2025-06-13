package com.morrison.vpnmanager.exception;

public class VpnManagerException extends RuntimeException {
    public VpnManagerException(String message) {
        super(message);
    }

    public VpnManagerException(String message, Throwable cause) {
        super(message, cause);
    }
}
