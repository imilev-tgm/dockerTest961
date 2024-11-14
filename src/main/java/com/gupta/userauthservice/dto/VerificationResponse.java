package com.gupta.userauthservice.dto;

import com.gupta.userauthservice.entity.Role;
import lombok.*;

import java.util.Set;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class VerificationResponse {

    @NonNull
    private Set<Role> roles;
}
