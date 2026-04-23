package com.example.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "user-service")
public record UserServiceProperties(String baseUrl, @DefaultValue("true") boolean enabled) {
}
