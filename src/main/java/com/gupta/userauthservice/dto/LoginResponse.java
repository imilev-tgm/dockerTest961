package com.gupta.userauthservice.dto;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {

    @NonNull
    private String token;

    @NonNull
    private String message;
}
