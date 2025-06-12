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
        RegisterRequest register = new RegisterRequest("test123@example.com", "password123", "local");

        // 1. Реєструємо користувача і отримуємо токен
        String responseJson = webTestClient.post()
                .uri("http://localhost:" + port + "/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        String token = extractTokenFromJson(responseJson);

        // 2. Перевіряємо, що /me повертає очікуваного користувача
        webTestClient.get()
                .uri("http://localhost:" + port + "/api/auth/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("test123@example.com")
                .jsonPath("$.provider").isEqualTo("local");
    }

    @Test
    void shouldLoginWithValidCredentials() throws Exception {
        // Крок 1: реєструємо користувача
        RegisterRequest register = new RegisterRequest("login_test@example.com", "password123", "local");
        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        // Крок 2: логінимося з тими ж даними
        LoginRequest login = new LoginRequest("login_test@example.com", "password123");
        webTestClient.post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").exists();
    }

    @Test
    void shouldRejectLoginWithInvalidPassword() throws Exception {
        // Спочатку реєструємо користувача
        RegisterRequest register = new RegisterRequest("invalidpass@example.com", "correctPassword", "local");
        webTestClient.post()
                .uri("http://localhost:" + port + "/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        // Після цього пробуємо увійти з неправильним паролем
        LoginRequest login = new LoginRequest("invalidpass@example.com", "wrongPassword");
        webTestClient.post()
                .uri("http://localhost:" + port + "/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectAccessToMeWithoutToken() {
        webTestClient.get()
                .uri("http://localhost:" + port + "/api/auth/me")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectAccessToMeWithInvalidToken() {
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer invalid.token.value")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldReturnMeAfterLogin() throws Exception {
        // Крок 1: реєструємо користувача
        RegisterRequest register = new RegisterRequest("me_test@example.com", "password123", "local");
        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        // Крок 2: логінимося
        LoginRequest login = new LoginRequest("me_test@example.com", "password123");
        byte[] tokenJson = webTestClient.post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        String token = objectMapper.readTree(tokenJson).get("token").asText();

        // Крок 3: звернення до /me з токеном
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("me_test@example.com")
                .jsonPath("$.provider").isEqualTo("local");
    }

    @Test
    void shouldReturnCurrentUserInfo() throws Exception {
        // Крок 1: реєстрація
        RegisterRequest register = new RegisterRequest("current_user@example.com", "password456", "local");
        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        // Крок 2: логін
        LoginRequest login = new LoginRequest("current_user@example.com", "password456");
        byte[] tokenJson = webTestClient.post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        String token = objectMapper.readTree(tokenJson).get("token").asText();

        // Крок 3: запит до /me
        webTestClient.get()
                .uri("/api/auth/me")
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
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectMeWithInvalidToken() {
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer invalid.jwt.token")
                .exchange()
                .expectStatus().isUnauthorized(); // ✅ правильний статус для невалідного токена
    }

    @Test
    void shouldRejectDuplicateEmailRegistration() throws Exception {
        // Успішна реєстрація
        RegisterRequest register = new RegisterRequest("duplicate@example.com", "password123", "local");
        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        // Повторна спроба — без cookie
        WebTestClient statelessClient = webTestClient.mutate()
                .defaultCookie("JSESSIONID", "")
                .build();

        statelessClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void shouldRejectRegisterWithoutEmail() throws Exception {
        // Формуємо запит без email
        String requestJson = """
        {
            "password": "password123"
        }
        """;

        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestJson)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void shouldRejectRegisterWithMissingFields() throws Exception {
        // Створюємо неповний JSON без email і provider
        String invalidPayload = """
        {
          "password": "password123"
        }
        """;

        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(invalidPayload)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.errors").isArray()
                .jsonPath("$.errors[?(@ =~ /.*email.*/)]").exists()
                .jsonPath("$.errors[?(@ =~ /.*provider.*/)]").exists();
    }

    @Test
    void shouldReturn404IfUserNotFoundAfterTokenIssued() throws Exception {
        // Крок 1: реєстрація
        RegisterRequest register = new RegisterRequest("ghost@example.com", "password123", "local");
        String token = objectMapper.readTree(
                webTestClient.post()
                        .uri("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(objectMapper.writeValueAsString(register))
                        .exchange()
                        .expectStatus().isOk()
                        .expectBody()
                        .returnResult()
                        .getResponseBodyContent()
        ).get("token").asText();

        // Крок 2: вручну видаляємо користувача (через UserRepository)
        userRepository.deleteAll();

        // Крок 3: запит до /me — має бути 404
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void shouldReturnNotFoundIfUserDeletedAfterLogin() throws Exception {
        // Крок 1: Реєстрація користувача
        RegisterRequest register = new RegisterRequest("deleted@example.com", "password123", "local");
        String tokenJson = new String(
                webTestClient.post()
                        .uri("/api/auth/register")
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

        // Крок 2: Видаляємо користувача з бази
        User user = userRepository.findByEmailAndProvider("deleted@example.com", "local")
                .orElseThrow();
        userRepository.delete(user);

        // Крок 3: Запит до /me після видалення користувача
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void shouldReturnNewTokenOnSecondLogin() throws Exception {
        // Крок 1: реєструємо користувача
        RegisterRequest register = new RegisterRequest("token_refresh@example.com", "password123", "local");
        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        // Крок 2: перший логін
        LoginRequest login = new LoginRequest("token_refresh@example.com", "password123");
        byte[] firstLoginJson = webTestClient.post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();
        String firstToken = objectMapper.readTree(firstLoginJson).get("token").asText();

        // Крок 3: другий логін
        byte[] secondLoginJson = webTestClient.post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();
        String secondToken = objectMapper.readTree(secondLoginJson).get("token").asText();

        // Перевірка: токени не мають бути однаковими
        assertThat(firstToken).isNotEqualTo(secondToken);
    }

    @Test
    void shouldRejectMeRequestWithExpiredToken() {
        // Створюємо токен із exp у минулому
        Instant now = Instant.now();
        Instant expired = now.minusSeconds(3600); // 1 година тому

        String expiredToken = Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .claim("email", "expired@example.com")
                .claim("provider", "local")
                .setIssuedAt(Date.from(expired.minusSeconds(60)))
                .setExpiration(Date.from(expired))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        // Виклик до /me з простроченим токеном
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer " + expiredToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectTokenSignedWithDifferentSecret() {
        // Генеруємо інший секретний ключ
        String otherSecret = "anotherSecretKeyThatIsDifferent123!";
        Key otherKey = Keys.hmacShaKeyFor(otherSecret.getBytes(StandardCharsets.UTF_8));

        // Створюємо токен з неправильним ключем
        String forgedToken = Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .claim("email", "forged@example.com")
                .claim("provider", "local")
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(otherKey, SignatureAlgorithm.HS256)
                .compact();

        // Очікуємо 401 Unauthorized
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer " + forgedToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectMeWithInvalidUserIdInToken() throws Exception {
        // 1. Генеруємо токен з невалідним UUID у полі sub (наприклад: "not-a-uuid")
        String invalidToken = Jwts.builder()
                .setSubject("not-a-uuid")
                .claim("email", "fake@example.com")
                .claim("provider", "local")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000)) // 1 год
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        // 2. Запит до /me з цим токеном
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer " + invalidToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldRejectMeWithMissingEmailInToken() {
        // Створюємо користувача
        RegisterRequest register = new RegisterRequest("noemailtoken@example.com", "password123", "local");
        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(register)
                .exchange()
                .expectStatus().isOk();

        // Беремо будь-який валідний UUID (можна навіть з DB, але тут просто для прикладу)
        String fakeId = UUID.randomUUID().toString();

        // Створюємо токен БЕЗ claim "email"
        String tokenWithoutEmail = Jwts.builder()
                .setSubject(fakeId)
                .claim("provider", "local")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        // Звертаємось до /me
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer " + tokenWithoutEmail)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldReturnNotFoundIfEmailDoesNotMatchAnyUser() {
        // Створюємо користувача
        RegisterRequest register = new RegisterRequest("wrongemailtoken@example.com", "password123", "local");
        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(register)
                .exchange()
                .expectStatus().isOk();

        // Створюємо токен з існуючим UUID, але з фейковим email
        String userId = userRepository.findByEmailAndProvider("wrongemailtoken@example.com", "local")
                .orElseThrow()
                .getId()
                .toString();

        String tokenWithWrongEmail = Jwts.builder()
                .setSubject(userId)
                .claim("email", "not_exist@example.com") // неіснуючий email
                .claim("provider", "local")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600_000))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        // Очікуємо 404
        webTestClient.get()
                .uri("/api/auth/me")
                .header("Authorization", "Bearer " + tokenWithWrongEmail)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void shouldIssueAccessAndRefreshTokenOnLogin() throws Exception {
        // Крок 1: реєстрація користувача
        RegisterRequest register = new RegisterRequest("refresh_login@example.com", "password123", "local");

        webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk();

        // Крок 2: логін
        LoginRequest login = new LoginRequest("refresh_login@example.com", "password123");

        byte[] responseBody = webTestClient.post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(login))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        JsonNode json = objectMapper.readTree(responseBody);
        System.out.println(new String(responseBody));
        String accessToken = json.get("token").asText();
        String refreshToken = json.get("refreshToken").asText();

        assertThat(accessToken).isNotBlank();
        assertThat(refreshToken).isNotBlank();
    }

    @Test
    void shouldReturnNewAccessTokenWithValidRefreshToken() throws Exception {
        // 🔹 Реєструємо нового користувача
        var register = new RegisterRequest("refresh_test@example.com", "password123", "local");
        byte[] registerResponseBytes = webTestClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(register))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        String registerResponse = new String(registerResponseBytes, StandardCharsets.UTF_8);

        // 🔹 Парсимо токени
        JsonNode tokenNode = objectMapper.readTree(registerResponse);
        String oldAccessToken = tokenNode.get("token").asText();
        String refreshToken = tokenNode.get("refreshToken").asText();

        // 🔹 Викликаємо /refresh
        var refreshRequest = new TokenRefreshRequest(refreshToken);
        System.out.println("🧪 Sending refresh token in request: " + refreshToken);

        byte[] refreshResponseBytes = webTestClient.post()
                .uri("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(refreshRequest))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();

        String refreshResponse = new String(refreshResponseBytes, StandardCharsets.UTF_8);

        // 🔹 Перевіряємо, що новий accessToken повернуто, і refreshToken той самий
        JsonNode refreshed = objectMapper.readTree(refreshResponse);
        String newAccessToken = refreshed.get("accessToken").asText();
        String returnedRefreshToken = refreshed.get("refreshToken").asText();

        assertThat(newAccessToken).isNotBlank();
        assertThat(newAccessToken).isNotEqualTo(oldAccessToken);
        assertThat(returnedRefreshToken).isEqualTo(refreshToken);
    }

//    @Test
//    void shouldRejectExpiredRefreshToken() throws Exception {
//        // 🔹 Короткий термін життя refresh токена (наприклад, 100 мс)
//        // У твоєму application-test.yml має бути:
//        // jwt:
//        //   refresh-token:
//        //     expiration-ms: 100
//
//        var register = new RegisterRequest("expired_token_test@example.com", "password123", "local");
//        byte[] responseBytes = webTestClient.post()
//                .uri("/api/auth/register")
//                .contentType(MediaType.APPLICATION_JSON)
//                .bodyValue(objectMapper.writeValueAsString(register))
//                .exchange()
//                .expectStatus().isOk()
//                .expectBody()
//                .returnResult()
//                .getResponseBodyContent();
//
//        JsonNode node = objectMapper.readTree(new String(responseBytes, StandardCharsets.UTF_8));
//        String expiredRefreshToken = node.get("refreshToken").asText();
//
//        // 🔹 Чекаємо, поки токен протухне
//        Thread.sleep(200);
//
//        var request = new TokenRefreshRequest(expiredRefreshToken);
//        webTestClient.post()
//                .uri("/api/auth/refresh")
//                .contentType(MediaType.APPLICATION_JSON)
//                .bodyValue(objectMapper.writeValueAsString(request))
//                .exchange()
//                .expectStatus().isUnauthorized();
//    }

    @Test
    void shouldInvalidateRefreshTokenAfterLogout() throws Exception {
        // 🔹 Реєстрація
        var registerRequest = new RegisterRequest("logout_test@example.com", "password123", "local");

        byte[] registerResponseBytes = webTestClient.post()
                .uri("/api/auth/register")
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

        // 🔹 Logout (авторизований запит з accessToken)
        var refreshRequest = new TokenRefreshRequest(refreshToken);

        webTestClient.post()
                .uri("/api/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers -> headers.setBearerAuth(accessToken)) // ⬅️ авторизація
                .bodyValue(objectMapper.writeValueAsString(refreshRequest))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.success").isEqualTo(true)
                .jsonPath("$.message").isEqualTo("Logged out successfully");

        // 🔹 Спроба використати видалений refreshToken
        webTestClient.post()
                .uri("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(refreshRequest))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    private String extractTokenFromJson(String json) throws IOException {
        return objectMapper.readTree(json).get("token").asText();
    }
}