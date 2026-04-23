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
- `service/` — business logic: `AuthService`, `UserService`, `GoogleAuthService`, `RefreshTokenService`, `JwtService`, `CookieService`, `EmailService`, `EmailVerificationService`, `UserServiceClient`, `VerificationEmailListener`
- `security/` — `JwtAuthFilter` (reads JWT from cookies, sets SecurityContext)
- `entity/` — `User`, `RefreshToken` (auto-DDL via Hibernate)
- `event/` — `VerificationEmailEvent` (published after the register tx commits)
- `config/` — `SecurityConfig`, `PasswordConfig`, `JwtProperties`, `InternalApiProperties`, `UserServiceProperties`, `UserServiceClientConfig`, `InternalApiKeyValidator`
- `exception/` — `GlobalExceptionHandler`, `UserServiceUnavailableException`, `UserServiceAuthException`

**Auth flow:**
1. `POST /register` → create user (`emailVerified=false`), call user-service `ensureProfile`, issue JWT + refresh cookies, return 201 + `UserResponse` body. Verification email is sent from a `@TransactionalEventListener(AFTER_COMMIT)` so it only fires if the whole transaction commits.
2. `GET /verify-email?token=` → validate token, mark verified, re-issue JWT + refresh cookies, redirect to frontend
3. `POST /login` → authenticate, issue cookies regardless of `emailVerified` status
4. Both tokens are HTTP-only, Secure, SameSite=None cookies; domain set via `COOKIE_DOMAIN` env var
5. `JwtAuthFilter` validates access token on protected requests
6. `POST /refresh` exchanges refresh token for new pair
7. Google OAuth via `GET /oauth/google?code=...` — first-time OAuth users auto-verified; new users get an `ensureProfile` call in the same transaction.
8. `DELETE /delete` → local delete commits, then user-service `deleteProfile` is called fire-and-forget (failures logged, client still gets 200).

**emailVerified semantics:** `emailVerified=false` users can log in and access normal endpoints. There is no server-side gate on delete (see commit 0269d84). Downstream services decide their own policies using the `emailVerified` JWT claim.

**JWT claims:** `sub` (user ID), `email`, `provider`, `emailVerified` — frontend reads `emailVerified` to show verification banner or restrict UI. `/me` is the authoritative source for `emailVerified`; frontend should re-fetch on window-focus since the JWT claim can be up to 15 min stale (access token lifetime).

**Token security:**
- Refresh tokens: stored as `SHA-256(token + salt)`, never raw
- Verification tokens: stored as `SHA-256(token)`, raw token only in the email link

**Email verification:** `EmailVerificationService` manages token lifecycle (generate/validate/resend with cooldown). `EmailService.sendVerificationEmail()` runs `@Async`. For the register flow it's dispatched from `VerificationEmailListener` on `@TransactionalEventListener(AFTER_COMMIT)` so a rolled-back registration (e.g., user-service outage) does not send an email. SMTP failures are logged, not propagated. Outbound port 587 may be blocked on DigitalOcean (unblock request pending).

## User-service integration

Auth-service provisions a matching profile in the sibling `user-service` on every registration + first-time Google login, and deletes it on account delete.

- **Client:** `UserServiceClient` uses a Spring `RestClient` bean (`userServiceRestClient`) built with `JdkClientHttpRequestFactory`, 2s connect / 5s read timeout, `X-Internal-Api-Key` default header. **Pinned to HTTP/1.1** — the JDK client otherwise tries ALPN upgrade against Tomcat and hangs (see commit 9145c2b).
- **Call-sites:**
  - `AuthService.register()` — `@Transactional`, calls `ensureProfile` after the local save; a 5xx/timeout throws `UserServiceUnavailableException` → the auth row is rolled back → 502 to the client → no verification email (the email event listener runs only AFTER_COMMIT).
  - `GoogleAuthService.processOAuthCallback()` — `@Transactional`; `ensureProfile` fires only inside `findOrCreateUser`'s `orElseGet` (new-user branch) — repeat logins do not hit user-service.
  - `AuthController.deleteAccount()` — calls `deleteProfile` **after** `userService.deleteById` commits, wrapped in try/catch. Asymmetry is deliberate: register rolls back; delete logs and continues (orphans are reconciled out-of-band).
- **Status handling:** `POST /api/v1/users/internal/create` treats 200 + 201 as success (idempotent). 401 → `UserServiceAuthException` (maps to 500, surfaces `INTERNAL_API_KEY` mismatch). 5xx / IO → `UserServiceUnavailableException` (502). `DELETE /api/v1/users/internal/{id}` treats 204 + 404 as success.
- **Feature flag:** `user-service.enabled` (default `true`) short-circuits both calls when disabled. The transactional boundary and email-deferral are always on.
- **Shared secrets:** `INTERNAL_API_KEY` **and** `JWT_SECRET` must be byte-identical on both services. A mismatch is the single most likely integration bug. User-service stores the live values in `/home/deploy/user-service/.env` on the droplet.

## Database

PostgreSQL — connection details come from environment variables. Schema is auto-managed by Hibernate (`ddl-auto: update`).

Key tables: `users` (UUID PK, email+provider unique, `email_verified`, `verification_token` hash, `verification_token_issued_at`), `refresh_tokens` (one per user, stores hash+salt+status).

**Caveat:** `ddl-auto: update` cannot add `NOT NULL` columns to tables with existing rows. If a new non-nullable column is added, run `ALTER TABLE ... ADD COLUMN ... DEFAULT ...` manually on the server before deploying.

Integration tests use Testcontainers (PostgreSQL 15) — Docker must be running.

## Environment

CI/CD writes `.env` on the server from GitHub secrets/variables. Required values:

| Variable | Source |
|---|---|
| `JWT_SECRET` | GitHub secret `ENV_JWT_SECRET` — base64 HMAC key, **byte-identical to user-service's** |
| `SPRING_DATASOURCE_URL/USERNAME/PASSWORD` | GitHub secrets |
| `GOOGLE_CLIENT_SECRET` | GitHub secret |
| `MAIL_USERNAME` | GitHub secret — Gmail address |
| `MAIL_PASSWORD` | GitHub secret — Gmail app password (16 chars, no spaces) |
| `INTERNAL_API_KEY` | GitHub secret — ≥32 chars, **identical to user-service's value**. Startup fails fast if missing/short. |
| `APP_BASE_URL` | GitHub variable — e.g. `https://auth.savuliak.com` |
| `FRONTEND_URL` | GitHub variable — e.g. `https://savuliak.com` |
| `CORS_ALLOWED_ORIGINS` | GitHub variable — e.g. `https://savuliak.com` |
| `COOKIE_DOMAIN` | GitHub variable — e.g. `savuliak.com` |
| `USER_SERVICE_BASE_URL` | GitHub variable — e.g. `http://user-service:8081` (docker DNS name on the shared network) |

JWT expiry: `jwt.access-token.expiration-ms` (15 min) and `jwt.refresh-token.expiration-ms` (30 days) in `application.yml`.

## Testing

Integration tests mock `EmailService` **and `UserServiceClient`** with `@MockBean` — no SMTP, no running user-service needed. `application-test.yml` sets a dummy ≥32-char `internal.api-key` so the startup validator passes. Raw verification tokens are captured via `ArgumentCaptor` on the mocked `emailService.sendVerificationEmail()` call, not read from the DB (the DB stores the hash). Rollback invariants (auth-row absent + email not sent when `ensureProfile` throws) are asserted directly against the Testcontainers DB.

## Deployment

CI/CD via `.github/workflows/deploy.yml`: push to `main` → Maven build → rsync to server → `docker compose up -d --build --no-deps auth-service` over SSH (postgres is deliberately left alone, see commit 5a260bf). External docker networks that must exist on the server before the deploy:
- `gateway-network` — the nginx reverse proxy.
- `user-service_default` — created by the user-service stack. Auth-service attaches to this as external so `http://user-service:8081` resolves via docker DNS (commit 7a924d2). User-service's postgres port is **not** published on the host — access via this shared network, or via SSH tunnel for pgAdmin.

The deploy waits for `Started AuthServiceApplication` in the container logs and fails fast on `password authentication failed`.

**DB password — single source of truth:** `docker-compose.yml` reads `POSTGRES_USER` / `POSTGRES_PASSWORD` from `.env` (`${SPRING_DATASOURCE_USERNAME}` / `${SPRING_DATASOURCE_PASSWORD}`). This only affects the **initial** volume creation — postgres stores the password inside the data volume on first init and ignores `POSTGRES_PASSWORD` on subsequent starts.

**Rotating the DB password (GitHub secret `ENV_SPRING_DATASOURCE_PASSWORD`):** rotating the secret alone will break the deploy, because the existing volume still has the old password. Procedure:
1. On the server, ALTER the DB user to the new password *before* merging the secret rotation:
   ```
   docker exec auth-postgres psql -U postgres -c "ALTER USER postgres WITH PASSWORD '<new>';"
   ```
2. Update the GitHub secret.
3. Push / redeploy.

**Recovery if auth-service is returning 500s with `password authentication failed` in logs** (drift between `.env` and the volume's stored password):
```
cd /home/deploy/auth-service
PW=$(grep '^SPRING_DATASOURCE_PASSWORD=' .env | cut -d= -f2-)
docker exec auth-postgres psql -U postgres -c "ALTER USER postgres WITH PASSWORD '$PW';"
docker compose restart auth-service
```

## Wiping data in production

Truncate without touching schema or flyway history:
```
ssh deploy@<droplet> "docker exec auth-postgres psql -U postgres -d auth_db \
  -c 'TRUNCATE TABLE refresh_tokens, users CASCADE;'"
ssh deploy@<droplet> "docker exec user-service-postgres-1 psql -U postgres -d user_service \
  -c 'TRUNCATE TABLE users CASCADE;'"
```
Any browser still holding old cookies gets 404 on `/me` and can just register again.
