package com.example.authservice.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class CookieService {

    @Value("${cookie.domain:}")
    private String cookieDomain;

    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        return getValueFromCookie(request, "refreshToken");
    }

    public String getAccessTokenFromCookie(HttpServletRequest request) {
        return getValueFromCookie(request, "token");
    }

    public String getValueFromCookie(HttpServletRequest request, String key) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (key.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public Cookie createHttpOnlyCookie(String key, String value, int maxAge) {
        Cookie cookie = new Cookie(key, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "None");
        if (cookieDomain != null && !cookieDomain.isBlank()) {
            cookie.setDomain(cookieDomain);
        }
        return cookie;
    }

    public void setRefreshToken(String refreshToken, HttpServletResponse servletResponse) {
        Cookie cookie = createHttpOnlyCookie("refreshToken", refreshToken, (int) Duration.ofDays(30).getSeconds());
        servletResponse.addCookie(cookie);
    }

    public void setAccessToken(String token, HttpServletResponse servletResponse) {
        Cookie cookie = createHttpOnlyCookie("token", token, (int) Duration.ofMinutes(15).getSeconds());
        servletResponse.addCookie(cookie);
    }
}
