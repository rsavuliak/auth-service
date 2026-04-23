package com.example.authservice.service;

import com.example.authservice.config.UserServiceProperties;
import com.example.authservice.exception.UserServiceAuthException;
import com.example.authservice.exception.UserServiceUnavailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.UUID;

@Service
public class UserServiceClient {

    private static final Logger log = LoggerFactory.getLogger(UserServiceClient.class);

    private final RestClient userServiceRestClient;
    private final UserServiceProperties userServiceProperties;

    public UserServiceClient(@Qualifier("userServiceRestClient") RestClient userServiceRestClient,
                             UserServiceProperties userServiceProperties) {
        this.userServiceRestClient = userServiceRestClient;
        this.userServiceProperties = userServiceProperties;
    }

    public void ensureProfile(UUID id, String email) {
        if (!userServiceProperties.enabled()) {
            log.debug("User Service disabled; skipping ensureProfile for id={}", id);
            return;
        }

        log.info("ensureProfile start id={} email={}", id, email);
        try {
            userServiceRestClient.post()
                    .uri("/api/v1/users/internal/create")
                    .body(Map.of("id", id.toString(), "email", email))
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        if (status == 200 || status == 201) {
                            return null;
                        }
                        if (status == 401) {
                            throw new UserServiceAuthException(
                                    "User Service rejected INTERNAL_API_KEY (401) — config mismatch");
                        }
                        throw new UserServiceUnavailableException(
                                "User Service returned " + status + " for ensureProfile");
                    });
            log.info("ensureProfile success id={}", id);
        } catch (UserServiceAuthException | UserServiceUnavailableException e) {
            log.error("ensureProfile failed id={}: {}", id, e.getMessage());
            throw e;
        } catch (ResourceAccessException e) {
            log.error("ensureProfile transport failure id={}: {}", id, e.getMessage());
            throw new UserServiceUnavailableException("User Service unreachable: " + e.getMessage(), e);
        } catch (RuntimeException e) {
            log.error("ensureProfile unexpected error id={}", id, e);
            throw new UserServiceUnavailableException("Unexpected error calling User Service: " + e.getMessage(), e);
        }
    }

    public void deleteProfile(UUID id) {
        if (!userServiceProperties.enabled()) {
            log.debug("User Service disabled; skipping deleteProfile for id={}", id);
            return;
        }

        log.info("deleteProfile start id={}", id);
        try {
            userServiceRestClient.delete()
                    .uri("/api/v1/users/internal/{id}", id)
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        if (status == 204 || status == 404) {
                            return null;
                        }
                        throw new UserServiceUnavailableException(
                                "User Service returned " + status + " for deleteProfile");
                    });
            log.info("deleteProfile success id={}", id);
        } catch (UserServiceUnavailableException e) {
            log.error("deleteProfile failed id={}: {}", id, e.getMessage());
            throw e;
        } catch (ResourceAccessException e) {
            log.error("deleteProfile transport failure id={}: {}", id, e.getMessage());
            throw new UserServiceUnavailableException("User Service unreachable: " + e.getMessage(), e);
        } catch (RuntimeException e) {
            log.error("deleteProfile unexpected error id={}", id, e);
            throw new UserServiceUnavailableException("Unexpected error calling User Service: " + e.getMessage(), e);
        }
    }
}
