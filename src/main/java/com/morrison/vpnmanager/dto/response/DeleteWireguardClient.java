package com.morrison.vpnmanager.dto.response;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class DeleteWireguardClient {
    @NotBlank(message = "Public key must not be blank")
    private String publicKey;
    @NotNull(message = "Scheduler Job ID must not be null")
    private Integer schedulerJobId;

}
