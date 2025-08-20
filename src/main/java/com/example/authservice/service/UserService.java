package com.example.authservice.service;

import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Optional<User> findUser(String email, String provider) {
        return userRepository.findByEmailAndProvider(email, provider);
    }

    public Optional<User> findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public User findUserById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    public User createUser(String email, String provider) {
        return createUser(email, null, provider);
    }

    public User createUser(String email, String password, String provider) {
        User user = new User();
        user.setEmail(email);
        if (password != null) {
            user.setPassword(passwordEncoder.encode(password));
        }
        user.setProvider(provider);
        user.setProviderId(provider + "_" + email);
        user.setCreatedAt(Instant.now());
        userRepository.save(user);
        return user;
    }

    @Transactional
    public void deleteById(UUID userId) {
        User user = findUserById(userId);
        userRepository.delete(user);
    }
}
