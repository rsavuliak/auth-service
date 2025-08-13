package com.example.authservice.security;

import com.example.authservice.entity.RefreshToken;
import com.example.authservice.entity.User;
import com.example.authservice.repository.RefreshTokenRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Duration expiration;
    private final Clock clock;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            @Value("${jwt.refresh-token.expiration-ms}") long expirationMs,
            Clock clock
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.expiration = Duration.ofMillis(expirationMs);
        this.clock = clock;
    }


    public String generateRawToken() {
        byte[] randomBytes = new byte[64];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public String generateSalt() {
        byte[] saltBytes = new byte[16];
        secureRandom.nextBytes(saltBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(saltBytes);
    }

    public String hashWithSalt(String value, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] hashedBytes = md.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public Pair<RefreshToken, String> replaceRefreshToken(String rawToken) {
        RefreshToken refreshToken = validateRefreshToken(rawToken);
        return createRefreshToken(refreshToken.getUser());
    }

    @Transactional
    public Pair<RefreshToken, String> createRefreshToken(User user) {
        deleteByUser(user);

        String tokenId = UUID.randomUUID().toString();
        String secret = generateRawToken();
        String salt = generateSalt();
        String tokenHash = hashWithSalt(secret, salt);

        RefreshToken refreshToken = new RefreshToken(
                user,
                tokenId,
                tokenHash,
                salt,
                clock.instant().plus(expiration),
                "",
                ""
        );
        refreshTokenRepository.save(refreshToken);
        return  Pair.of(refreshToken, tokenId + "." + secret);
    }

    public String parseTokenId(String rawToken) {
        return parseRawToken(rawToken)[0];
    }

    public String parseToken(String rawToken) {
        return parseRawToken(rawToken)[1];
    }

    public String[] parseRawToken(String rawToken) {
        String[] parts = rawToken.split("\\.", 2);
        if (parts.length != 2) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token format");
        }
        return parts;
    }

    public boolean validateRefreshToken(User user, String rawToken) {
        return refreshTokenRepository.findByUser(user)
                .filter(rt -> rt.getStatus() == RefreshToken.TokenStatus.ACTIVE)
                .filter(rt -> rt.getExpiryDate().isAfter(clock.instant()))
                .map(rt -> hashWithSalt(parseToken(rawToken), rt.getSalt()).equals(rt.getTokenHash()))
                .orElse(false);
    }

    public RefreshToken validateRefreshToken(String rawToken) {
        String tokenId = parseTokenId(rawToken);
        String tokenValue = parseToken(rawToken);

        return refreshTokenRepository.findByTokenId(tokenId)
                .filter(token -> token.getStatus() == RefreshToken.TokenStatus.ACTIVE)
                .filter(token -> token.getExpiryDate().isAfter(clock.instant()))
                .filter(token -> hashWithSalt(tokenValue, token.getSalt()).equals(token.getTokenHash()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token"));
    }

    @Transactional
    public void revokeToken(User user) {
        refreshTokenRepository.findByUser(user)
                .ifPresent(rt -> {
                    rt.setStatus(RefreshToken.TokenStatus.REVOKED);
                    refreshTokenRepository.save(rt);
                });
    }

    @Transactional
    public void deleteByUser(User user) {
        refreshTokenRepository.deleteByUserId(user.getId());
    }

    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.deleteByTokenId(parseTokenId(token));
    }
}