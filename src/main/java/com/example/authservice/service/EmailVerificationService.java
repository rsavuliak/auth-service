package com.example.authservice.service;

import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class EmailVerificationService {

    private final UserRepository userRepository;

    @Value("${app.email-verification.token-expiry-minutes}")
    private int expiryMinutes;

    @Value("${app.email-verification.resend-cooldown-minutes}")
    private int cooldownMinutes;

    public EmailVerificationService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional
    public String generateToken(User user) {
        String raw = UUID.randomUUID().toString();
        Instant now = Instant.now();
        user.setVerificationToken(sha256(raw));
        user.setVerificationTokenIssuedAt(now);
        user.setVerificationTokenExpiry(now.plus(Duration.ofMinutes(expiryMinutes)));
        userRepository.save(user);
        return raw;
    }

    @Transactional
    public User validateToken(String token) {
        User user = userRepository.findByVerificationToken(sha256(token))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid verification token"));

        if (Instant.now().isAfter(user.getVerificationTokenExpiry())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Verification token has expired");
        }

        user.setEmailVerified(true);
        user.setVerificationToken(null);
        user.setVerificationTokenIssuedAt(null);
        user.setVerificationTokenExpiry(null);
        userRepository.save(user);
        return user;
    }

    @Transactional
    public String resendToken(String email) {
        User user = userRepository.findByEmailAndProvider(email, "local")
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (user.isEmailVerified()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is already verified");
        }

        if (user.getVerificationTokenIssuedAt() != null) {
            Duration timeSinceIssued = Duration.between(user.getVerificationTokenIssuedAt(), Instant.now());
            if (timeSinceIssued.toMinutes() < cooldownMinutes) {
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                        "Please wait before requesting another verification email");
            }
        }

        return generateToken(user);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
