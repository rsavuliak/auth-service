package com.example.authservice.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class GoogleUserInfo {
    private String id;
    private String email;
    private String name;

    @JsonProperty("picture")
    private String pictureUrl;
}
