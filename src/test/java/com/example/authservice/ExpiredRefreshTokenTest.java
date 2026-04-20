package com.example.authservice;

import com.example.authservice.dto.*;
import com.example.authservice.repository.RefreshTokenRepository;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.service.EmailService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.cdimascio.dotenv.Dotenv;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.example.authservice.AuthControllerIntegrationTest.getAccessTokenCookie;
import static com.example.authservice.AuthControllerIntegrationTest.getRefreshTokenCookie;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verify;

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

    @MockBean
    private EmailService emailService;

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

    private static final String apiPath = "/api/v1/auth";

    private WebTestClient.ResponseSpec registerAndVerify(String email, String password) {
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new RegisterRequest(email, password))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.ACCEPTED);

        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendVerificationEmail(eq(email), tokenCaptor.capture());
        clearInvocations(emailService);
        String rawToken = tokenCaptor.getValue();

        return webTestClient.get()
                .uri(apiPath + "/verify-email?token=" + rawToken)
                .exchange()
                .expectStatus().is3xxRedirection()
                .expectHeader().exists("Set-Cookie");
    }

    @Test
    void shouldRejectExpiredRefreshToken() throws Exception {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("login_test@example.com", "password123");

        String tokenCookie = getAccessTokenCookie(verifyResponse);
        String refreshTokenCookie = getRefreshTokenCookie(verifyResponse);

        Thread.sleep(200);

        webTestClient.post()
                .uri(apiPath + "/refresh")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
