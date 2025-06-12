package com.example.authservice.provider;

import com.example.authservice.dto.AuthRequest;
import com.example.authservice.entity.User;

public interface AuthProvider {
    boolean supports(String provider); // Наприклад: "local", "google"
    User authenticate(AuthRequest request);
}