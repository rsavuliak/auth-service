package com.example.authservice.provider;

import com.example.authservice.dto.AuthRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class LocalAuthProvider implements AuthProvider {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public LocalAuthProvider(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public boolean supports(String provider) {
        return "local".equalsIgnoreCase(provider);
    }

    @Override
    public User authenticate(AuthRequest request) {
        return userRepository.findByEmail(request.email())
                .filter(user -> "local".equalsIgnoreCase(user.getProvider()))
                .filter(user -> passwordEncoder.matches(request.password(), user.getPassword()))
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));
    }

    public User register(RegisterRequest request) {
        if (userRepository.findByEmail(request.email())
                .filter(u -> "local".equalsIgnoreCase(u.getProvider()))
                .isPresent()) {
            throw new RuntimeException("User with this email already exists");
        }

        User user = new User();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setProvider("local");
        return userRepository.save(user);
    }
}