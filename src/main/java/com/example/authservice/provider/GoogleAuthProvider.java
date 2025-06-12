package com.example.authservice.provider;

import com.example.authservice.dto.AuthRequest;
import com.example.authservice.entity.User;
import org.springframework.stereotype.Component;

@Component
public class GoogleAuthProvider implements AuthProvider {

    @Override
    public boolean supports(String provider) {
        return "google".equalsIgnoreCase(provider);
    }

    @Override
    public User authenticate(AuthRequest request) {
        // Тут має бути логіка перевірки Google ID token (через OAuth2 library)
        throw new UnsupportedOperationException("Google login not implemented yet.");
    }
}