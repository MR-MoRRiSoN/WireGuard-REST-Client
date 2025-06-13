package com.morrison.vpnmanager.service;

import com.morrison.vpnmanager.enums.VpnStatuses;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AppStartupRunner {
    private final VpnManagerService vpnManagerService;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationEvent() throws IOException, InterruptedException {
       rebootWireguardOnAppRun();
    }

    private void rebootWireguardOnAppRun() throws IOException, InterruptedException {
        if (vpnManagerService.isWireGuardRunning().status() == VpnStatuses.STARTED)
            if (vpnManagerService.stopWireGuard().status() == VpnStatuses.STOPPED)
                if (vpnManagerService.startWireGuard().status() == VpnStatuses.STARTED)
                    if (vpnManagerService.deleteAllTimeSchedule())
                        System.out.println("VPN MANAGER RESTARTED");
                    else
                        System.out.println("Failed to start VPN MANAGER");
                else if (vpnManagerService.startWireGuard().status() == VpnStatuses.STARTED)
                    System.out.println("VPN MANAGER STARTED");
                else
                    System.out.println("Failed to start VPN MANAGER");

    }
}
