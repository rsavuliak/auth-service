package com.example.authservice;

import com.example.authservice.dto.LoginRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.entity.User;
import com.example.authservice.repository.RefreshTokenRepository;
import com.example.authservice.repository.UserRepository;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

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
        RegisterRequest registerRequest = new RegisterRequest("testuser@example.com", "password123");

        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("testuser@example.com");
    }

    @Test
    void shouldLoginWithValidCredentials() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        assertThat(tokenCookie).isNotBlank();
        assertThat(refreshTokenCookie).isNotBlank();

        LoginRequest login = new LoginRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec loginResponse = webTestClient.post()
                .uri(apiPath + "/login")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        tokenCookie = getAccessTokenCookie(loginResponse);
        refreshTokenCookie = getRefreshTokenCookie(loginResponse);

        assertThat(tokenCookie).isNotBlank();
        assertThat(refreshTokenCookie).isNotBlank();
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
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        LoginRequest login = new LoginRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec loginResponse = webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("login_test@example.com")
                .jsonPath("$.provider").isEqualTo("local");
    }

    @Test
    void shouldReturnCurrentUserInfo() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        LoginRequest login = new LoginRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec loginResponse = webTestClient.post()
                .uri(apiPath + "/login")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        tokenCookie = getAccessTokenCookie(loginResponse);
        refreshTokenCookie = getRefreshTokenCookie(loginResponse);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("login_test@example.com")
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
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        userRepository.deleteAll();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void shouldReturnNotFoundIfUserDeletedAfterLogin() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("deleted@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        User user = userRepository.findByEmailAndProvider("deleted@example.com", "local").orElseThrow();
        userRepository.delete(user);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void shouldReturnNewTokenOnSecondLogin() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        assertThat(tokenCookie).isNotBlank();
        assertThat(refreshTokenCookie).isNotBlank();

        LoginRequest login = new LoginRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec loginResponse = webTestClient.post()
                .uri(apiPath + "/login")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        tokenCookie = getAccessTokenCookie(loginResponse);
        refreshTokenCookie = getRefreshTokenCookie(loginResponse);

        String firstToken = getAccessTokenFromCookie(tokenCookie);

        WebTestClient.ResponseSpec secondLoginResponse = webTestClient.post()
                .uri(apiPath + "/login")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        tokenCookie = getAccessTokenCookie(secondLoginResponse);

        String secondToken = getAccessTokenFromCookie(tokenCookie);
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
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        assertThat(tokenCookie).isNotBlank();
        assertThat(refreshTokenCookie).isNotBlank();

        LoginRequest login = new LoginRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec loginResponse = webTestClient.post()
                .uri(apiPath + "/login")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        tokenCookie = getAccessTokenCookie(registerResponse);
        refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        assertThat(tokenCookie).isNotBlank();
        assertThat(refreshTokenCookie).isNotBlank();
    }

    @Test
    void shouldReturnNewAccessTokenWithValidRefreshToken() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        assertThat(tokenCookie).isNotBlank();
        assertThat(refreshTokenCookie).isNotBlank();

        String oldAccessToken = getAccessTokenFromCookie(tokenCookie);
        String oldRefreshToken = getRefreshTokenFromCookie(refreshTokenCookie);

        assertThat(oldAccessToken).isNotBlank();
        assertThat(oldRefreshToken).isNotBlank();

        LoginRequest login = new LoginRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec refreshResponse = webTestClient.post()
                .uri(apiPath + "/refresh")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String newAccessTokenCookie = getAccessTokenCookie(refreshResponse);
        String newRefreshTokenCookie = getRefreshTokenCookie(refreshResponse);

        assertThat(newAccessTokenCookie).isNotBlank();
        assertThat(newRefreshTokenCookie).isNotBlank();

        String newAccessToken = getAccessTokenFromCookie(newAccessTokenCookie);
        String newRefreshToken = getRefreshTokenFromCookie(newRefreshTokenCookie);

        assertThat(newAccessToken).isNotBlank();
        assertThat(newRefreshToken).isNotBlank();

        assertThat(newAccessToken).isNotEqualTo(oldAccessToken);
        assertThat(newRefreshToken).isNotEqualTo(oldRefreshToken);
    }

    @Test
    void shouldInvalidateRefreshTokenAfterLogout() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        WebTestClient.ResponseSpec refreshResponse = webTestClient.post()
                .uri(apiPath + "/logout")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        tokenCookie = getAccessTokenCookie(refreshResponse);
        refreshTokenCookie = getRefreshTokenCookie(refreshResponse);

        webTestClient.post()
                .uri(apiPath + "/refresh")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    private String extractTokenFromJson(String json) throws IOException {
        return objectMapper.readTree(json).get("token").asText();
    }

    public static String getValueFromCookie(String cookie, String key) {
        return Arrays.stream(cookie.split(";"))
                .map(String::trim)
                .filter(s -> s.startsWith(key))
                .map(s -> s.substring("token=".length()))
                .findFirst()
                .orElse(null);
    }

    public static String getAccessTokenFromCookie(String cookie) {
        return getValueFromCookie(cookie, "token=");
    }

    public static String getRefreshTokenFromCookie(String cookie) {
        return getValueFromCookie(cookie, "refreshToken=");
    }

    public static String getAccessTokenCookie(WebTestClient.ResponseSpec authResponse) {
        return getCookie(authResponse, "token=");
    }

    public static String getRefreshTokenCookie(WebTestClient.ResponseSpec authResponse) {
        return getCookie(authResponse, "refreshToken=");
    }

    private static String getCookie(WebTestClient.ResponseSpec authResponse, String key) {
        return authResponse
                .returnResult(String.class)
                .getResponseHeaders()
                .get(HttpHeaders.SET_COOKIE)
                .stream()
                .filter(s -> s.contains(key))
                .findFirst()
                .orElse("");
    }


    @Test
    void shouldDeleteUser() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("login_test@example.com", "password123");
        WebTestClient.ResponseSpec registerResponse = webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registerRequest)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String tokenCookie = getAccessTokenCookie(registerResponse);
        String refreshTokenCookie = getRefreshTokenCookie(registerResponse);

        WebTestClient.ResponseSpec refreshResponse = webTestClient.delete()
                .uri(apiPath + "/delete")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isOk();

        LoginRequest login = new LoginRequest("login_test@example.com", "password123");
        webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(userRepository.findByEmail("login_test@example.com").isPresent()).isFalse();
    }
}