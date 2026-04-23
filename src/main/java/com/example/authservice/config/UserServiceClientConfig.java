package com.example.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;

@Configuration
public class UserServiceClientConfig {

    @Bean
    public RestClient userServiceRestClient(UserServiceProperties userServiceProperties,
                                            InternalApiProperties internalApiProperties) {
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(2))
                .build();

        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(Duration.ofSeconds(5));

        return RestClient.builder()
                .baseUrl(userServiceProperties.baseUrl())
                .defaultHeader("X-Internal-Api-Key", internalApiProperties.apiKey())
                .requestFactory(factory)
                .build();
    }
}
