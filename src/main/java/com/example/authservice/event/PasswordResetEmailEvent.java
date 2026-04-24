package com.example.authservice.event;

public record PasswordResetEmailEvent(String email, String token) {
}
