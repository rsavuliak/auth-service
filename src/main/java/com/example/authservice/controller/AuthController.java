package com.example.authservice.controller;

import com.example.authservice.dto.*;
import com.example.authservice.entity.RefreshToken;
import com.example.authservice.entity.User;
import com.example.authservice.security.JwtService;
import com.example.authservice.security.RefreshTokenService;
import com.example.authservice.service.AuthService;
import com.example.authservice.service.CookieService;
import com.example.authservice.service.EmailService;
import com.example.authservice.service.EmailVerificationService;
import com.example.authservice.service.UserService;
import com.example.authservice.service.UserServiceClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;
    private final CookieService cookieService;
    private final EmailVerificationService emailVerificationService;
    private final EmailService emailService;
    private final UserServiceClient userServiceClient;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request,
                                                  HttpServletResponse servletResponse) {
        AuthResponse authResponse = authService.register(request);
        cookieService.setAccessToken(authResponse.token(), servletResponse);
        cookieService.setRefreshToken(authResponse.refreshToken(), servletResponse);
        User user = userService.findUser(request.email(), "local").orElseThrow();
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new UserResponse(user.getId().toString(), user.getEmail(), user.getProvider(), user.isEmailVerified()));
    }

    @GetMapping("/verify-email")
    public ResponseEntity<Void> verifyEmail(@RequestParam String token, HttpServletResponse servletResponse) {
        User user = emailVerificationService.validateToken(token);
        String accessToken = jwtService.generateToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user).getSecond();
        cookieService.setAccessToken(accessToken, servletResponse);
        cookieService.setRefreshToken(refreshToken, servletResponse);
        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, frontendUrl)
                .build();
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        try {
            String token = emailVerificationService.resendToken(request.email());
            emailService.sendVerificationEmail(request.email(), token);
        } catch (ResponseStatusException e) {
            if (e.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) throw e;
            // swallow NOT_FOUND / BAD_REQUEST — don't reveal whether the email exists or is already verified
        }
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(@RequestBody @Valid LoginRequest request, HttpServletResponse servletResponse) {
        AuthResponse authResponse = authService.login(request);
        cookieService.setAccessToken(authResponse.token(), servletResponse);
        cookieService.setRefreshToken(authResponse.refreshToken(), servletResponse);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal UserPrincipal principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        User user = userService.findUserById(principal.id());
        UserResponse response = new UserResponse(
                user.getId().toString(),
                user.getEmail(),
                user.getProvider(),
                user.isEmailVerified()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<Void> refreshToken(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String requestRefreshToken = cookieService.getRefreshTokenFromCookie(servletRequest);
        if (requestRefreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Pair<RefreshToken, String> tokenData = refreshTokenService.replaceRefreshToken(requestRefreshToken);
        String refreshToken = tokenData.getSecond();
        String newAccessToken = jwtService.generateToken(tokenData.getFirst().getUser());

        cookieService.setAccessToken(newAccessToken, servletResponse);
        cookieService.setRefreshToken(refreshToken, servletResponse);

        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String refreshToken = cookieService.getRefreshTokenFromCookie(servletRequest);
        if (refreshToken != null) {
            refreshTokenService.deleteByToken(refreshToken);
        }
        servletResponse.addCookie(cookieService.createHttpOnlyCookie("refreshToken", "", 0));
        servletResponse.addCookie(cookieService.createHttpOnlyCookie("token", "", 0));
        return ResponseEntity.ok(new ApiResponse(true, "Logged out successfully"));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteAccount(@AuthenticationPrincipal UserPrincipal principal,
                                              HttpServletResponse servletResponse) {
        userService.deleteById(principal.id());
        try {
            userServiceClient.deleteProfile(principal.id());
        } catch (Exception e) {
            log.error("User Service deleteProfile failed for id={}; profile may be orphaned until reconciliation",
                    principal.id(), e);
        }
        servletResponse.addCookie(cookieService.createHttpOnlyCookie("refreshToken", "", 0));
        servletResponse.addCookie(cookieService.createHttpOnlyCookie("token", "", 0));
        return ResponseEntity.ok().build();
    }
}