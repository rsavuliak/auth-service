package com.example.authservice.event;

public record VerificationEmailEvent(String email, String token) {
}
