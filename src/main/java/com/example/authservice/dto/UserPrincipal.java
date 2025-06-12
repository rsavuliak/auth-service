package com.example.authservice.dto;

import java.io.Serializable;
import java.util.UUID;

public record UserPrincipal(UUID id, String email) implements Serializable {}