package com.morrison.vpnmanager.exception;

public class CommandTimeoutException extends VpnManagerException {
    public CommandTimeoutException(String message) {
        super(message);
    }
}
