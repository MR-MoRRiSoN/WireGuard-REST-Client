package com.morrison.vpnmanager.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/hi")
public class ApplicationController {
    @GetMapping
    private String hi() {
        return "Hi, I'm RemotePlay VPN Manager";
    }
}
