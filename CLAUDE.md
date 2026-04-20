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
docker compose up --build           # Production (use V2 — docker compose, not docker-compose)

# Test
./mvnw test                                                             # All tests
./mvnw test -Dtest=AuthControllerIntegrationTest                        # Single class
./mvnw test -Dtest=AuthControllerIntegrationTest#shouldReturnCurrentUserAfterRegister  # Single method
```

## Architecture

Standard Spring Boot 3.2 layered architecture (`controller → service → repository`), stateless JWT authentication with a refresh token pattern.

**Package layout:** `com.example.authservice`
- `controller/` — REST endpoints (`/api/v1/auth`)
- `service/` — business logic: `AuthService`, `UserService`, `GoogleAuthService`, `RefreshTokenService`, `JwtService`, `CookieService`, `EmailService`, `EmailVerificationService`
- `security/` — `JwtAuthFilter` (reads JWT from cookies, sets SecurityContext)
- `entity/` — `User`, `RefreshToken` (auto-DDL via Hibernate)
- `config/` — `SecurityConfig` (CORS + security filter chain), `PasswordConfig`, `JwtConfig`
- `exception/` — `GlobalExceptionHandler`

**Auth flow:**
1. `POST /register` → create user (`emailVerified=false`), send verification email, return 202 (no cookies)
2. `GET /verify-email?token=` → validate token, mark verified, issue JWT + refresh cookies, redirect to frontend
3. `POST /login` → authenticate, issue cookies regardless of `emailVerified` status
4. Both tokens are HTTP-only, Secure, SameSite=None cookies; domain set via `COOKIE_DOMAIN` env var
5. `JwtAuthFilter` validates access token on protected requests
6. `POST /refresh` exchanges refresh token for new pair
7. Google OAuth via `GET /oauth/google?code=...` — users auto-verified on creation

**JWT claims:** `sub` (user ID), `email`, `provider`, `emailVerified` — frontend reads `emailVerified` to show verification banner or enforce limited rights.

**Token security:**
- Refresh tokens: stored as `SHA-256(token + salt)`, never raw
- Verification tokens: stored as `SHA-256(token)`, raw token only in the email link

**Email verification:** `EmailVerificationService` manages token lifecycle (generate/validate/resend with cooldown). `EmailService.sendVerificationEmail()` runs `@Async` — SMTP failures are logged, not propagated. Outbound port 587 may be blocked on DigitalOcean (unblock request pending).

## Database

PostgreSQL — connection details come from environment variables. Schema is auto-managed by Hibernate (`ddl-auto: update`).

Key tables: `users` (UUID PK, email+provider unique, `email_verified`, `verification_token` hash, `verification_token_issued_at`), `refresh_tokens` (one per user, stores hash+salt+status).

**Caveat:** `ddl-auto: update` cannot add `NOT NULL` columns to tables with existing rows. If a new non-nullable column is added, run `ALTER TABLE ... ADD COLUMN ... DEFAULT ...` manually on the server before deploying.

Integration tests use Testcontainers (PostgreSQL 15) — Docker must be running.

## Environment

CI/CD writes `.env` on the server from GitHub secrets/variables. Required values:

| Variable | Source |
|---|---|
| `JWT_SECRET` | GitHub secret — base64-encoded HMAC key |
| `SPRING_DATASOURCE_URL/USERNAME/PASSWORD` | GitHub secrets |
| `GOOGLE_CLIENT_SECRET` | GitHub secret |
| `MAIL_USERNAME` | GitHub secret — Gmail address |
| `MAIL_PASSWORD` | GitHub secret — Gmail app password (16 chars, no spaces) |
| `APP_BASE_URL` | GitHub variable — e.g. `https://auth.savuliak.com` |
| `FRONTEND_URL` | GitHub variable — e.g. `https://savuliak.com` |
| `CORS_ALLOWED_ORIGINS` | GitHub variable — e.g. `https://savuliak.com` |
| `COOKIE_DOMAIN` | GitHub variable — e.g. `savuliak.com` |

JWT expiry: `jwt.access-token.expiration-ms` (15 min) and `jwt.refresh-token.expiration-ms` (30 days) in `application.yml`.

## Testing

Integration tests mock `EmailService` with `@MockBean` — no SMTP needed. Raw verification tokens are captured via `ArgumentCaptor` on the mocked `emailService.sendVerificationEmail()` call, not read from the DB (the DB stores the hash).

## Deployment

CI/CD via `.github/workflows/deploy.yml`: push to `main` → Maven build → rsync to server → `docker compose up --build` over SSH. External `gateway-network` Docker network must exist on the server (used by nginx reverse proxy).

**Known server issue:** if `docker compose down` + `up` recreates the postgres container, the existing volume retains the old password. Fix: `docker exec auth-postgres psql -U postgres -c "ALTER USER postgres WITH PASSWORD 'postgres';"` then restart the auth service.
