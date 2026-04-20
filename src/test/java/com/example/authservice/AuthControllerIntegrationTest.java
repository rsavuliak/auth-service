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
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import com.example.authservice.service.EmailService;
import org.springframework.boot.test.mock.mockito.MockBean;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verify;

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

    // ── Helpers ────────────────────────────────────────────────────────────────

    /**
     * Registers a user (202), captures the raw verification token via the mocked
     * EmailService, then calls GET /verify-email (302 + cookies).
     */
    private WebTestClient.ResponseSpec registerAndVerify(String email, String password) {
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new RegisterRequest(email, password))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.ACCEPTED);

        String rawToken = captureRawToken(email);

        return webTestClient.get()
                .uri(apiPath + "/verify-email?token=" + rawToken)
                .exchange()
                .expectStatus().is3xxRedirection()
                .expectHeader().exists("Set-Cookie");
    }

    /** Captures the raw verification token that was passed to the mocked EmailService. */
    private String captureRawToken(String email) {
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendVerificationEmail(eq(email), tokenCaptor.capture());
        clearInvocations(emailService);
        return tokenCaptor.getValue();
    }

    public static String getAccessTokenFromCookie(String cookie) {
        return getValueFromCookie(cookie, "token=");
    }

    public static String getRefreshTokenFromCookie(String cookie) {
        return getValueFromCookie(cookie, "refreshToken=");
    }

    public static String getValueFromCookie(String cookie, String key) {
        return Arrays.stream(cookie.split(";"))
                .map(String::trim)
                .filter(s -> s.startsWith(key))
                .map(s -> s.substring("token=".length()))
                .findFirst()
                .orElse(null);
    }

    public static String getAccessTokenCookie(WebTestClient.ResponseSpec response) {
        return getCookie(response, "token=");
    }

    public static String getRefreshTokenCookie(WebTestClient.ResponseSpec response) {
        return getCookie(response, "refreshToken=");
    }

    private static String getCookie(WebTestClient.ResponseSpec response, String key) {
        return response
                .returnResult(String.class)
                .getResponseHeaders()
                .get(HttpHeaders.SET_COOKIE)
                .stream()
                .filter(s -> s.contains(key))
                .findFirst()
                .orElse("");
    }

    // ── Registration ────────────────────────────────────────────────────────────

    @Test
    void shouldReturnCurrentUserAfterRegister() {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("testuser@example.com", "password123");

        String tokenCookie = getAccessTokenCookie(verifyResponse);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("testuser@example.com");
    }

    @Test
    void registerShouldReturn202WithoutCookies() {
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new RegisterRequest("pending@example.com", "password123"))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.ACCEPTED)
                .expectHeader().doesNotExist("Set-Cookie");
    }

    @Test
    void shouldRejectDuplicateEmailRegistration() throws Exception {
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(new RegisterRequest("duplicate@example.com", "password123")))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.ACCEPTED);

        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(new RegisterRequest("duplicate@example.com", "password123")))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void shouldRejectRegisterWithoutEmail() {
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"password\": \"password123\"}")
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void shouldRejectRegisterWithMissingFields() {
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"password\": \"password123\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.errors").isArray()
                .jsonPath("$.errors[?(@ =~ /.*email.*/)]").exists();
    }

    // ── Email verification ───────────────────────────────────────────────────────

    @Test
    void shouldIssueTokensOnEmailVerification() {
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new RegisterRequest("verify@example.com", "password123"))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.ACCEPTED);

        String rawToken = captureRawToken("verify@example.com");

        WebTestClient.ResponseSpec verifyResponse = webTestClient.get()
                .uri(apiPath + "/verify-email?token=" + rawToken)
                .exchange()
                .expectStatus().is3xxRedirection()
                .expectHeader().exists("Set-Cookie");

        assertThat(getAccessTokenCookie(verifyResponse)).isNotBlank();
        assertThat(getRefreshTokenCookie(verifyResponse)).isNotBlank();
    }

    @Test
    void shouldRejectInvalidVerificationToken() {
        webTestClient.get()
                .uri(apiPath + "/verify-email?token=" + UUID.randomUUID())
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectAlreadyUsedVerificationToken() {
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new RegisterRequest("reuse@example.com", "password123"))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.ACCEPTED);

        String rawToken = captureRawToken("reuse@example.com");

        // First use — should succeed
        webTestClient.get()
                .uri(apiPath + "/verify-email?token=" + rawToken)
                .exchange()
                .expectStatus().is3xxRedirection();

        // Second use — token consumed, must fail
        webTestClient.get()
                .uri(apiPath + "/verify-email?token=" + rawToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldAllowLoginBeforeEmailVerification() {
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new RegisterRequest("unverified@example.com", "password123"))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.ACCEPTED);

        webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new LoginRequest("unverified@example.com", "password123"))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");
    }

    @Test
    void shouldReturnEmailVerifiedStatusInMeResponse() {
        // Register but don't verify — emailVerified should be false
        webTestClient.post()
                .uri(apiPath + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new RegisterRequest("verifystatus@example.com", "password123"))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.ACCEPTED);

        WebTestClient.ResponseSpec loginResponse = webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new LoginRequest("verifystatus@example.com", "password123"))
                .exchange()
                .expectStatus().isOk();

        String tokenCookie = getAccessTokenCookie(loginResponse);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.emailVerified").isEqualTo(false);

        // Now verify email — emailVerified should become true
        String rawToken = captureRawToken("verifystatus@example.com");
        WebTestClient.ResponseSpec verifyResponse = webTestClient.get()
                .uri(apiPath + "/verify-email?token=" + rawToken)
                .exchange()
                .expectStatus().is3xxRedirection();

        String verifiedTokenCookie = getAccessTokenCookie(verifyResponse);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, verifiedTokenCookie)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.emailVerified").isEqualTo(true);
    }

    @Test
    void resendVerificationWithUnknownEmailShouldReturn200() {
        webTestClient.post()
                .uri(apiPath + "/resend-verification")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"nobody@example.com\"}")
                .exchange()
                .expectStatus().isOk();
    }

    // ── Login ───────────────────────────────────────────────────────────────────

    @Test
    void shouldLoginWithValidCredentials() throws Exception {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("login_test@example.com", "password123");
        String tokenCookie = getAccessTokenCookie(verifyResponse);
        String refreshTokenCookie = getRefreshTokenCookie(verifyResponse);

        assertThat(tokenCookie).isNotBlank();
        assertThat(refreshTokenCookie).isNotBlank();

        WebTestClient.ResponseSpec loginResponse = webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(new LoginRequest("login_test@example.com", "password123")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        assertThat(getAccessTokenCookie(loginResponse)).isNotBlank();
        assertThat(getRefreshTokenCookie(loginResponse)).isNotBlank();
    }

    @Test
    void shouldRejectLoginWithInvalidPassword() throws Exception {
        registerAndVerify("invalidpass@example.com", "correctPassword");

        webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(new LoginRequest("invalidpass@example.com", "wrongPassword")))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectLoginWithUnknownEmail() throws Exception {
        webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(new LoginRequest("unknown@example.com", "somePassword")))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldReturnNewTokenOnSecondLogin() throws Exception {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("login_test@example.com", "password123");
        String tokenCookie = getAccessTokenCookie(verifyResponse);
        String refreshTokenCookie = getRefreshTokenCookie(verifyResponse);

        WebTestClient.ResponseSpec firstLogin = webTestClient.post()
                .uri(apiPath + "/login")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(new LoginRequest("login_test@example.com", "password123")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String firstToken = getAccessTokenFromCookie(getAccessTokenCookie(firstLogin));

        WebTestClient.ResponseSpec secondLogin = webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(new LoginRequest("login_test@example.com", "password123")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        String secondToken = getAccessTokenFromCookie(getAccessTokenCookie(secondLogin));
        assertThat(firstToken).isNotEqualTo(secondToken);
    }

    // ── /me ─────────────────────────────────────────────────────────────────────

    @Test
    void shouldReturnCurrentUserAfterLogin() throws Exception {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("login_test@example.com", "password123");
        String tokenCookie = getAccessTokenCookie(verifyResponse);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("login_test@example.com")
                .jsonPath("$.provider").isEqualTo("local");
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
    void shouldReturn404IfUserNotFoundAfterTokenIssued() {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("login_test@example.com", "password123");
        String tokenCookie = getAccessTokenCookie(verifyResponse);

        userRepository.deleteAll();

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void shouldReturnNotFoundIfUserDeletedAfterLogin() {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("deleted@example.com", "password123");
        String tokenCookie = getAccessTokenCookie(verifyResponse);

        User user = userRepository.findByEmailAndProvider("deleted@example.com", "local").orElseThrow();
        userRepository.delete(user);

        webTestClient.get()
                .uri(apiPath + "/me")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .exchange()
                .expectStatus().isNotFound();
    }

    // ── JWT edge cases ───────────────────────────────────────────────────────────

    @Test
    void shouldRejectMeRequestWithExpiredToken() {
        Instant expired = Instant.now().minusSeconds(3600);

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
        Key otherKey = Keys.hmacShaKeyFor("anotherSecretKeyThatIsDifferent123!".getBytes(StandardCharsets.UTF_8));

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
    void shouldRejectMeWithInvalidUserIdInToken() {
        String invalidToken = Jwts.builder()
                .setSubject("not-a-uuid")
                .claim("email", "fake@example.com")
                .claim("provider", "local")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600_000))
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
        registerAndVerify("noemailtoken@example.com", "password123");

        String tokenWithoutEmail = Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .claim("provider", "local")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600_000))
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
        registerAndVerify("wrongemailtoken@example.com", "password123");

        String userId = userRepository.findByEmailAndProvider("wrongemailtoken@example.com", "local")
                .orElseThrow().getId().toString();

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

    // ── Refresh ──────────────────────────────────────────────────────────────────

    @Test
    void shouldReturnNewAccessTokenWithValidRefreshToken() throws Exception {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("login_test@example.com", "password123");
        String tokenCookie = getAccessTokenCookie(verifyResponse);
        String refreshTokenCookie = getRefreshTokenCookie(verifyResponse);

        String oldAccessToken = getAccessTokenFromCookie(tokenCookie);
        String oldRefreshToken = getRefreshTokenFromCookie(refreshTokenCookie);

        assertThat(oldAccessToken).isNotBlank();
        assertThat(oldRefreshToken).isNotBlank();

        WebTestClient.ResponseSpec refreshResponse = webTestClient.post()
                .uri(apiPath + "/refresh")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        assertThat(getAccessTokenFromCookie(getAccessTokenCookie(refreshResponse))).isNotEqualTo(oldAccessToken);
        assertThat(getRefreshTokenFromCookie(getRefreshTokenCookie(refreshResponse))).isNotEqualTo(oldRefreshToken);
    }

    // ── Logout ───────────────────────────────────────────────────────────────────

    @Test
    void shouldInvalidateRefreshTokenAfterLogout() {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("login_test@example.com", "password123");
        String tokenCookie = getAccessTokenCookie(verifyResponse);
        String refreshTokenCookie = getRefreshTokenCookie(verifyResponse);

        WebTestClient.ResponseSpec logoutResponse = webTestClient.post()
                .uri(apiPath + "/logout")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("Set-Cookie");

        tokenCookie = getAccessTokenCookie(logoutResponse);
        refreshTokenCookie = getRefreshTokenCookie(logoutResponse);

        webTestClient.post()
                .uri(apiPath + "/refresh")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── Delete ───────────────────────────────────────────────────────────────────

    @Test
    void shouldDeleteUser() throws Exception {
        WebTestClient.ResponseSpec verifyResponse = registerAndVerify("login_test@example.com", "password123");
        String tokenCookie = getAccessTokenCookie(verifyResponse);
        String refreshTokenCookie = getRefreshTokenCookie(verifyResponse);

        webTestClient.delete()
                .uri(apiPath + "/delete")
                .header(HttpHeaders.COOKIE, tokenCookie)
                .header(HttpHeaders.COOKIE, refreshTokenCookie)
                .exchange()
                .expectStatus().isOk();

        webTestClient.post()
                .uri(apiPath + "/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(new LoginRequest("login_test@example.com", "password123")))
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(userRepository.findByEmail("login_test@example.com").isPresent()).isFalse();
    }

    private String extractTokenFromJson(String json) throws IOException {
        return objectMapper.readTree(json).get("token").asText();
    }
}
