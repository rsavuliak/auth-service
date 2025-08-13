package com.example.authservice;

import com.example.authservice.dto.LoginRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.dto.TokenRefreshRequest;
import com.example.authservice.entity.User;
import com.example.authservice.repository.RefreshTokenRepository;
import com.example.authservice.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.cdimascio.dotenv.Dotenv;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class AuthControllerIntegrationTest {
    private static final String apiPath = "/api/v1/auth";

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

    @Test
    void shouldReturnCurrentUserAfterRegister() throws Exception {
        RegisterRequest register = new RegisterRequest("test123@example.com", "password123");

        String responseJson = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        String token = extractTokenFromJson(responseJson);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("test123@example.com")
                .jsonPath("$.provider").isEqualTo("local");
    }

    @Test
    void shouldLoginWithValidCredentials() throws Exception {
        RegisterRequest register = new RegisterRequest("login_test@example.com", "password123");
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        LoginRequest login = new LoginRequest("login_test@example.com", "password123");
        webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").exists();
    }

    @Test
    void shouldRejectLoginWithInvalidPassword() throws Exception {
        RegisterRequest register = new RegisterRequest("invalidpass@example.com", "correctPassword");
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        LoginRequest login = new LoginRequest("invalidpass@example.com", "wrongPassword");
        webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectAccessToMeWithoutToken() {
        webTestClient.get()
                .uri(apiPath + "/me")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectAccessToMeWithInvalidToken() {
        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer invalid.token.value")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldReturnMeAfterLogin() throws Exception {
        RegisterRequest register = new RegisterRequest("me_test@example.com", "password123");
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        LoginRequest login = new LoginRequest("me_test@example.com", "password123");
        byte[] tokenJson = webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        String token = objectMapper.readTree(tokenJson).get("token").asText();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("me_test@example.com")
                .jsonPath("$.provider").isEqualTo("local");
    }

    @Test
    void shouldReturnCurrentUserInfo() throws Exception {
        RegisterRequest register = new RegisterRequest("current_user@example.com", "password456");
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        LoginRequest login = new LoginRequest("current_user@example.com", "password456");
        byte[] tokenJson = webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        String token = objectMapper.readTree(tokenJson).get("token").asText();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("current_user@example.com")
                .jsonPath("$.provider").isEqualTo("local");
    }

    @Test
    void shouldRejectLoginWithUnknownEmail() throws Exception {
        LoginRequest login = new LoginRequest("unknown@example.com", "somePassword");

        webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectMeWithInvalidToken() {
        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer invalid.jwt.token")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectDuplicateEmailRegistration() throws Exception {
        RegisterRequest register = new RegisterRequest("duplicate@example.com", "password123");
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        WebTestClient statelessClient = webTestClient.mutate()
                .defaultCookie("JSESSIONID", "")
                .build();

        statelessClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void shouldRejectRegisterWithoutEmail() throws Exception {
        String requestJson = """
        {
            "password": "password123"
        }
        """;

        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestJson)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void shouldRejectRegisterWithMissingFields() throws Exception {
        String invalidPayload = """
        {
          "password": "password123"
        }
        """;

        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(invalidPayload)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.errors").isArray()
                .jsonPath("$.errors[?(@ =~ /.*email.*/)]").exists();
    }

    @Test
    void shouldReturn404IfUserNotFoundAfterTokenIssued() throws Exception {
        RegisterRequest register = new RegisterRequest("ghost@example.com", "password123");
        String token = objectMapper.readTree(
                webTestClient.post()
                        .uri(apiPath + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(objectMapper.writeValueAsString(register))
                        .exchange()
                        .expectStatus().isOk()
                        .expectBody()
                        .returnResult()
                        .getResponseBodyContent()
        ).get("token").asText();

        userRepository.deleteAll();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void shouldReturnNotFoundIfUserDeletedAfterLogin() throws Exception {
        RegisterRequest register = new RegisterRequest("deleted@example.com", "password123");
        String tokenJson = new String(
                webTestClient.post()
                        .uri(apiPath + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(objectMapper.writeValueAsString(register))
                        .exchange()
                        .expectStatus().isOk()
                        .expectBody()
                        .returnResult()
                        .getResponseBodyContent(),
                StandardCharsets.UTF_8
        );

        String token = objectMapper.readTree(tokenJson).get("token").asText();

        User user = userRepository.findByEmailAndProvider("deleted@example.com", "local")
                .orElseThrow();
        userRepository.delete(user);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void shouldReturnNewTokenOnSecondLogin() throws Exception {
        RegisterRequest register = new RegisterRequest("token_refresh@example.com", "password123");
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        LoginRequest login = new LoginRequest("token_refresh@example.com", "password123");
        byte[] firstLoginJson = webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();
        String firstToken = objectMapper.readTree(firstLoginJson).get("token").asText();

        byte[] secondLoginJson = webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();
        String secondToken = objectMapper.readTree(secondLoginJson).get("token").asText();

        assertThat(firstToken).isNotEqualTo(secondToken);
    }

    @Test
    void shouldRejectMeRequestWithExpiredToken() {
        Instant now = Instant.now();
        Instant expired = now.minusSeconds(3600);

        String expiredToken = Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .claim("email", "expired@example.com")
                .claim("provider", "local")
                .setIssuedAt(Date.from(expired.minusSeconds(60)))
                .setExpiration(Date.from(expired))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + expiredToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectTokenSignedWithDifferentSecret() {
        String otherSecret = "anotherSecretKeyThatIsDifferent123!";
        Key otherKey = Keys.hmacShaKeyFor(otherSecret.getBytes(StandardCharsets.UTF_8));

        String forgedToken = Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .claim("email", "forged@example.com")
                .claim("provider", "local")
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(otherKey, SignatureAlgorithm.HS256)
                .compact();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + forgedToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectMeWithInvalidUserIdInToken() throws Exception {
        String invalidToken = Jwts.builder()
                .setSubject("not-a-uuid")
                .claim("email", "fake@example.com")
                .claim("provider", "local")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + invalidToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectMeWithMissingEmailInToken() {
        RegisterRequest register = new RegisterRequest("noemailtoken@example.com", "password123");
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(register)
                .exchange()
                .expectStatus().isOk();

        String fakeId = UUID.randomUUID().toString();

        String tokenWithoutEmail = Jwts.builder()
                .setSubject(fakeId)
                .claim("provider", "local")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + tokenWithoutEmail)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldReturnNotFoundIfEmailDoesNotMatchAnyUser() {
        RegisterRequest register = new RegisterRequest("wrongemailtoken@example.com", "password123");
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(register)
                .exchange()
                .expectStatus().isOk();

        String userId = userRepository.findByEmailAndProvider("wrongemailtoken@example.com", "local")
                .orElseThrow()
                .getId()
                .toString();

        String tokenWithWrongEmail = Jwts.builder()
                .setSubject(userId)
                .claim("email", "not_exist@example.com")
                .claim("provider", "local")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600_000))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header("Authorization", "Bearer " + tokenWithWrongEmail)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldIssueAccessAndRefreshTokenOnLogin() throws Exception {
        RegisterRequest register = new RegisterRequest("refresh_login@example.com", "password123");

        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        LoginRequest login = new LoginRequest("refresh_login@example.com", "password123");

        byte[] responseBody = webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        JsonNode json = objectMapper.readTree(responseBody);
        String accessToken = json.get("token").asText();
        String refreshToken = json.get("refreshToken").asText();

        assertThat(accessToken).isNotBlank();
        assertThat(refreshToken).isNotBlank();
    }

    @Test
    void shouldReturnNewAccessTokenWithValidRefreshToken() throws Exception {
        var register = new RegisterRequest("refresh_test@example.com", "password123");
        byte[] registerResponseBytes = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        String registerResponse = new String(registerResponseBytes, StandardCharsets.UTF_8);

        JsonNode tokenNode = objectMapper.readTree(registerResponse);
        String oldAccessToken = tokenNode.get("token").asText();
        String refreshToken = tokenNode.get("refreshToken").asText();

        var refreshRequest = new TokenRefreshRequest(refreshToken);

        byte[] refreshResponseBytes = webTestClient.post()
                .uri(apiPath + "/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(refreshRequest))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        String refreshResponse = new String(refreshResponseBytes, StandardCharsets.UTF_8);

        JsonNode refreshed = objectMapper.readTree(refreshResponse);
        String newAccessToken = refreshed.get("accessToken").asText();
        String returnedRefreshToken = refreshed.get("refreshToken").asText();

        assertThat(newAccessToken).isNotBlank();
        assertThat(newAccessToken).isNotEqualTo(oldAccessToken);
        assertThat(returnedRefreshToken).isNotEqualTo(refreshToken);
    }

    @Test
    void shouldInvalidateRefreshTokenAfterLogout() throws Exception {
        var registerRequest = new RegisterRequest("logout_test@example.com", "password123");

        byte[] registerResponseBytes = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(registerRequest))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        JsonNode registerJson = objectMapper.readTree(new String(registerResponseBytes, StandardCharsets.UTF_8));
        String accessToken = registerJson.get("token").asText();
        String refreshToken = registerJson.get("refreshToken").asText();

        var refreshRequest = new TokenRefreshRequest(refreshToken);

        webTestClient.post()
                .uri(apiPath + "/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers -> headers.setBearerAuth(accessToken))
                .bodyValue(objectMapper.writeValueAsString(refreshRequest))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.success").isEqualTo(true)
                .jsonPath("$.message").isEqualTo("Logged out successfully");

        webTestClient.post()
                .uri(apiPath + "/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(refreshRequest))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    private String extractTokenFromJson(String json) throws IOException {
        return objectMapper.readTree(json).get("token").asText();
    }
}