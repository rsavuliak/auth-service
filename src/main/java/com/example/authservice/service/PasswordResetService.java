package com.example.authservice.service;

import com.example.authservice.entity.User;
import com.example.authservice.event.PasswordResetEmailEvent;
import com.example.authservice.repository.RefreshTokenRepository;
import com.example.authservice.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
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
public class PasswordResetService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher eventPublisher;

    @Value("${app.password-reset.token-expiry-minutes}")
    private int expiryMinutes;

    @Value("${app.password-reset.cooldown-minutes}")
    private int cooldownMinutes;

    public PasswordResetService(UserRepository userRepository,
                                RefreshTokenRepository refreshTokenRepository,
                                PasswordEncoder passwordEncoder,
                                ApplicationEventPublisher eventPublisher) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.eventPublisher = eventPublisher;
    }

    @Transactional
    public void initiateReset(String email) {
        User user = userRepository.findByEmailAndProvider(email, "local")
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, ""));

        if (user.getPasswordResetTokenIssuedAt() != null) {
            Duration timeSinceIssued = Duration.between(user.getPasswordResetTokenIssuedAt(), Instant.now());
            if (timeSinceIssued.toMinutes() < cooldownMinutes) {
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                        "Please wait before requesting another password reset");
            }
        }

        String raw = UUID.randomUUID().toString();
        Instant now = Instant.now();
        user.setPasswordResetToken(sha256(raw));
        user.setPasswordResetTokenIssuedAt(now);
        user.setPasswordResetTokenExpiry(now.plus(Duration.ofMinutes(expiryMinutes)));
        userRepository.save(user);

        eventPublisher.publishEvent(new PasswordResetEmailEvent(email, raw));
    }

    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        User user = userRepository.findByPasswordResetToken(sha256(rawToken))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token"));

        if (Instant.now().isAfter(user.getPasswordResetTokenExpiry())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token expired");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        user.setPasswordResetTokenIssuedAt(null);
        userRepository.save(user);

        refreshTokenRepository.deleteByUserId(user.getId());
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
