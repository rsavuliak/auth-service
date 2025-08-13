package com.example.authservice.controller;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.service.GoogleAuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class GoogleAuthController {

    private final GoogleAuthService googleAuthService;

    @GetMapping("/oauth/google")
    public ResponseEntity<Void> authenticate(@RequestParam("code") String code, HttpServletResponse response) {
        System.out.println("GoogleAuthController received code: " + code);
        AuthResponse tokens = googleAuthService.processOAuthCallback(code);

        setRefreshToken(tokens.refreshToken(), response);

        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, "https://savuliak.com/")
                .build();
    }

    public void setRefreshToken(String refreshToken, HttpServletResponse servletResponse) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) Duration.ofDays(30).getSeconds());
        cookie.setAttribute("SameSite", "Strict");
        servletResponse.addCookie(cookie);
    }
}
