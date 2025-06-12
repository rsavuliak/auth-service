package com.example.authservice.dto;

public record TokenRefreshResponse(String accessToken, String refreshToken) {}