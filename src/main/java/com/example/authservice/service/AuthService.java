package com.example.authservice.service;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.dto.LoginRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.security.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Optional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    public AuthResponse register(RegisterRequest request) {
        Optional<User> existingUser = userRepository.findByEmailAndProvider(request.email(), "local");
        if (existingUser.isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already in use");
        }

        User user = new User();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setProvider("local");
        user.setProviderId("local_" + request.email());
        user.setCreatedAt(Instant.now());

        userRepository.save(user);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = refreshTokenService.create(user).getToken();
        System.out.println("🟢 Created refresh token: " + refreshToken);
        return new AuthResponse(accessToken, refreshToken);
    }


    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmailAndProvider(request.email(), "local")
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
        }

        String accessToken = jwtService.generateToken(user);
        String refreshToken = refreshTokenService.create(user).getToken(); // Створює і зберігає в БД

        return new AuthResponse(accessToken, refreshToken);
    }
}