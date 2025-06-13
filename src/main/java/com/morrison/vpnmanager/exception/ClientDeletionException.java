package com.morrison.vpnmanager.exception;

public class ClientDeletionException extends RuntimeException {
    public ClientDeletionException(String errorMessage) {
        super(errorMessage);
    }
}
