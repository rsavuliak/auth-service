package com.example.authservice;

import com.example.authservice.dto.*;
import com.example.authservice.repository.RefreshTokenRepository;
import com.example.authservice.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.cdimascio.dotenv.Dotenv;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.context.support.TestPropertySourceUtils;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.example.authservice.AuthControllerIntegrationTest.getAccessTokenCookie;
import static com.example.authservice.AuthControllerIntegrationTest.getRefreshTokenCookie;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestPropertySource(properties = "jwt.refresh-token.expiration-ms=100")
public class ExpiredRefreshTokenTest {
    @LocalServerPort
    private int port;

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private ObjectMapper objectMapper;


    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.secret}")
    private String secretKey;

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
            .withDatabaseName("auth_db")
            .withUsername("postgres")
            .withPassword("postgres");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @BeforeAll
    static void loadEnv() {
        Dotenv dotenv = Dotenv.load();
        dotenv.entries().forEach(entry -> System.setProperty(entry.getKey(), entry.getValue()));
    }

    @BeforeEach
    void cleanDatabase() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    static class PropertyOverrideContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        @Override
        public void initialize(ConfigurableApplicationContext context) {
            TestPropertySourceUtils.addInlinedPropertiesToEnvironment(
                    context,
                    "jwt.refresh-token.expiration-ms=100"
            );
        }
    }

    @Test
    void shouldRejectExpiredRefreshToken() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath() + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        Thread.sleep(200);

        webTestClient.post()
                .uri(apiPath() + "/refresh")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    private String apiPath() {
        return "/api/v1/auth";
    }
}