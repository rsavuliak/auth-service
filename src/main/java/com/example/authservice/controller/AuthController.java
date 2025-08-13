package com.example.authservice.controller;

import com.example.authservice.dto.*;
import com.example.authservice.entity.RefreshToken;
import com.example.authservice.entity.User;
import com.example.authservice.security.JwtService;
import com.example.authservice.service.AuthService;
import com.example.authservice.security.RefreshTokenService;
import com.example.authservice.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        AuthResponse authResponse = authService.register(request);

        setRefreshToken(authResponse.refreshToken(), servletResponse);

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid LoginRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        AuthResponse authResponse = authService.login(request);

        setRefreshToken(authResponse.refreshToken(), servletResponse);

        return ResponseEntity.ok(authResponse);
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
                user.getProvider()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenRefreshResponse> refreshToken(@RequestBody TokenRefreshRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String requestRefreshToken = getRefreshTokenFromCookie(servletRequest);

        System.out.println();
        System.out.println();
        System.out.println("------> Token from Cookie : " + requestRefreshToken);
        System.out.println();
        System.out.println();

        Pair<RefreshToken, String> tokenData = refreshTokenService.replaceRefreshToken(requestRefreshToken);
        String refreshToken = tokenData.getSecond();
        String newAccessToken = jwtService.generateToken(tokenData.getFirst().getUser());

        setRefreshToken(refreshToken, servletResponse);

        return ResponseEntity.ok(new TokenRefreshResponse(newAccessToken,  refreshToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody TokenRefreshRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        refreshTokenService.deleteByToken(getRefreshTokenFromCookie(servletRequest));
        return ResponseEntity.ok(new ApiResponse(true, "Logged out successfully"));
    }

    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public void setRefreshToken(String refreshToken, HttpServletResponse servletResponse) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) Duration.ofDays(30).getSeconds());
        cookie.setAttribute("SameSite", "Strict");
        servletResponse.addCookie(cookie);
    }
}