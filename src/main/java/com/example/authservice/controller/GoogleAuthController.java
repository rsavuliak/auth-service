package com.example.authservice.controller;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.service.CookieService;
import com.example.authservice.service.GoogleAuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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
    private final CookieService cookieService;

    @GetMapping("/oauth/google")
    public ResponseEntity<Void> authenticate(@RequestParam("code") String code, HttpServletResponse servletResponse) {
        AuthResponse tokens = googleAuthService.processOAuthCallback(code);

        cookieService.setAccessToken(tokens.token(), servletResponse);
        cookieService.setRefreshToken(tokens.refreshToken(), servletResponse);

        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, "https://savuliak.com/")
                .build();
    }
}
