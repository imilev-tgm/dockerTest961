package com.gupta.userauthservice.dto;

import com.gupta.userauthservice.entity.Role;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Setter
@Getter
public class RegistrationRequest {

    private String username;
    private String email;
    private Set<Role> roles; // z.B. "ADMIN", "READER", "MODERATOR"
    private String password;
}
