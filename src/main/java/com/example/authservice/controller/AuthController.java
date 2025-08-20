package com.example.authservice.controller;

import com.example.authservice.dto.*;
import com.example.authservice.entity.RefreshToken;
import com.example.authservice.entity.User;
import com.example.authservice.security.JwtService;
import com.example.authservice.security.RefreshTokenService;
import com.example.authservice.service.AuthService;
import com.example.authservice.service.CookieService;
import com.example.authservice.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;
    private final CookieService cookieService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request, HttpServletResponse servletResponse) {
        AuthResponse authResponse = authService.register(request);
        cookieService.setAccessToken(authResponse.token(), servletResponse);
        cookieService.setRefreshToken(authResponse.refreshToken(), servletResponse);
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
                user.getProvider()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<Void> refreshToken(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String requestRefreshToken = cookieService.getRefreshTokenFromCookie(servletRequest);

        Pair<RefreshToken, String> tokenData = refreshTokenService.replaceRefreshToken(requestRefreshToken);
        String refreshToken = tokenData.getSecond();
        String newAccessToken = jwtService.generateToken(tokenData.getFirst().getUser());

        cookieService.setAccessToken(newAccessToken, servletResponse);
        cookieService.setRefreshToken(refreshToken, servletResponse);

        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        refreshTokenService.deleteByToken(cookieService.getRefreshTokenFromCookie(servletRequest));
        servletResponse.addCookie(cookieService.createHttpOnlyCookie("refreshToken", "", 0));
        servletResponse.addCookie(cookieService.createHttpOnlyCookie("token", "", 0));
        return ResponseEntity.ok(new ApiResponse(true, "Logged out successfully"));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteAccount(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {

        String accessToken = cookieService.getAccessTokenFromCookie(servletRequest);
        UserPrincipal userPrincipal = jwtService.extractUserPrincipal(accessToken);

        userService.deleteById(userPrincipal.id());
        return ResponseEntity.ok().build();
    }
}