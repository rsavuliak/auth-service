# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
./mvnw clean package -DskipTests   # Build JAR
./mvnw clean install                # Build with tests

# Run
./mvnw spring-boot:run              # Local dev
docker-compose -f docker-compose.dev.yml up  # Dev with Docker
docker-compose up --build           # Production

# Test
./mvnw test                                                             # All tests
./mvnw test -Dtest=AuthControllerIntegrationTest                        # Single class
./mvnw test -Dtest=AuthControllerIntegrationTest#shouldReturnCurrentUserAfterRegister  # Single method
```

## Architecture

Standard Spring Boot 3.2 layered architecture (`controller → service → repository`), stateless JWT authentication with a refresh token pattern.

**Package layout:** `com.example.authservice`
- `controller/` — REST endpoints (`/api/v1/auth`)
- `service/` — business logic: `AuthService`, `UserService`, `GoogleAuthService`, `RefreshTokenService`, `JwtService`, `CookieService`
- `security/` — `JwtAuthFilter` (reads JWT from cookies, sets SecurityContext)
- `entity/` — `User`, `RefreshToken` (auto-DDL via Hibernate)
- `config/` — `SecurityConfig`, `WebConfig` (CORS), `PasswordConfig`, `JwtConfig`
- `exception/` — `GlobalExceptionHandler`

**Auth flow:**
1. Register/login → generate JWT access token (15 min) + refresh token (30 days)
2. Both tokens stored as HTTP-only, Secure, SameSite=None cookies
3. `JwtAuthFilter` validates access token on protected requests
4. `POST /refresh` exchanges refresh token for new access token
5. Google OAuth via `GET /oauth/google?code=...`

**Refresh token security:** tokens are stored as `SHA-256(token + salt)` — only the hash and salt are persisted, never the raw token. The token ID is `uuid.secret` format.

## Database

PostgreSQL — connection details come from environment variables (see `.env`). Schema is auto-managed by Hibernate (`ddl-auto: update`).

Key tables: `users` (UUID PK, email+provider unique), `refresh_tokens` (one per user, stores hash+salt+status).

Integration tests use Testcontainers (PostgreSQL 15) — Docker must be running.

## Environment

Requires a `.env` file (for Docker Compose) with:
- `JWT_SECRET` — base64-encoded HMAC secret
- `SPRING_DATASOURCE_URL/USERNAME/PASSWORD`
- `GOOGLE_CLIENT_SECRET`
- `SPRING_PROFILES_ACTIVE=dev`

JWT expiry times are in `application.yml` under `jwt.expiration` (access) and `jwt.refresh-expiration` (refresh).

## Deployment

CI/CD via `.github/workflows/deploy.yml`: push to `main` → Maven build → rsync to server → `docker-compose up` over SSH. External `gateway-network` Docker network must exist on the server (used by reverse proxy).
