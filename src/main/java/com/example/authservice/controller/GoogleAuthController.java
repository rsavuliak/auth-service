package com.example.authservice.controller;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.service.GoogleAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class GoogleAuthController {

    private final GoogleAuthService googleAuthService;

    @GetMapping("/oauth/google")
    public ResponseEntity<AuthResponse> authenticate(@RequestParam("code") String code) {
        System.out.println("GoogleAuthController received code: " + code);
        AuthResponse tokens = googleAuthService.processOAuthCallback(code);
        return ResponseEntity.ok(tokens);
    }
}
