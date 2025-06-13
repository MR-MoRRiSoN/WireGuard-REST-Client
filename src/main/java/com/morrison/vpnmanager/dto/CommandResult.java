package com.morrison.vpnmanager.dto;


public record CommandResult(int exitCode, String output, String errorOutput) {
}
