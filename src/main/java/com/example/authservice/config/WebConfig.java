package com.example.authservice.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // Дозволити для всіх endpoints
                .allowedOrigins("https://savuliak.com") // Дозволити з будь-якого домену
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Які методи дозволені
                .allowedHeaders("*"); // Які заголовки дозволені
    }
}
