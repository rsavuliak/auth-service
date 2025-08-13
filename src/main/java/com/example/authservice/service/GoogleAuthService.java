package com.example.authservice.service;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.dto.GoogleTokenResponse;
import com.example.authservice.dto.GoogleUserInfo;
import com.example.authservice.entity.User;
import com.example.authservice.security.JwtService;
import com.example.authservice.security.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class GoogleAuthService {

    private final RestTemplate restTemplate;
    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Value("${google.client-id}")
    private String clientId;

    @Value("${google.client-secret}")
    private String clientSecret;

    @Value("${google.redirect-uri}")
    private String redirectUri;

    public AuthResponse processOAuthCallback(String code) {
        GoogleTokenResponse tokenResponse = getTokenFromGoogle(code);
        GoogleUserInfo userInfo = getUserInfoFromGoogle(tokenResponse.getAccessToken());
        User user = findOrCreateUser(userInfo.getEmail());

        String accessToken = jwtService.generateToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user).getSecond();

        return new AuthResponse(accessToken, refreshToken);
    }

    private GoogleTokenResponse getTokenFromGoogle(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("code", code);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("redirect_uri", redirectUri);
        form.add("grant_type", "authorization_code");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<GoogleTokenResponse> response = restTemplate.exchange(
                "https://oauth2.googleapis.com/token",
                HttpMethod.POST,
                request,
                GoogleTokenResponse.class
        );
        return response.getBody();
    }

    private GoogleUserInfo getUserInfoFromGoogle(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<GoogleUserInfo> response = restTemplate.exchange(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                HttpMethod.GET,
                request,
                GoogleUserInfo.class
        );

        return response.getBody();
    }

    private User findOrCreateUser(String email) {
        return userService.findUserByEmail(email)
                .map(user -> {
                    if (!"google".equals(user.getProvider())) {
                        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already in use");
                    }
                    return user;
                })
                .orElseGet(() -> userService.createUser(email, "google"));
    }
}