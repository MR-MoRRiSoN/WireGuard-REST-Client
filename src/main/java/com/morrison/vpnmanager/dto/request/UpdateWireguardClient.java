package com.morrison.vpnmanager.dto.request;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class UpdateWireguardClient {

    @NotBlank(message = "Public key must not be blank")
    private String publicKey;

    @NotNull(message = "Scheduler Job ID must not be null")
    private Integer schedulerJobId;

    @NotNull(message = "Scheduler end time must not be null")
    @Future(message = "Scheduler end time must be in the future")
    private LocalDateTime schedulerEndTime;

    @NotNull(message = "Client ip cannot be null")
    @Pattern(
            regexp = "^(\\d{1,3}\\.){3}\\d{1,3}$",
            message = "Client ip be a valid IPv4 address"
    )
    private String clientIp;
}
