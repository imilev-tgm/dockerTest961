package com.gupta.userauthservice.controller;

import com.gupta.userauthservice.dto.*;
import com.gupta.userauthservice.dto.RegistrationRequest;
import com.gupta.userauthservice.service.AuthenticationService;
import com.gupta.userauthservice.service.JwtService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.util.Set;

@Controller
@AllArgsConstructor
@RequestMapping("/auth") // da alle Endpunkte mit /auth starten
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    private final JwtService jwtService;

    @PostMapping("/admin/register")
    public ResponseEntity<RegistrationResponse> register(@RequestHeader("Authorization") String authHeader,
                                                           @RequestBody RegistrationRequest request) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            RegistrationResponse response = RegistrationResponse.builder()
                    .message("User is not authenticated")
                    .build();
            return ResponseEntity.status(403).body(response);
        }

        String token = authHeader.substring(7);
        Set<String> roles = jwtService.extractRoles(token);

        if (roles == null || !roles.contains("ADMIN")) {
            RegistrationResponse response = RegistrationResponse.builder()
                    .message("User is not privileged")
                    .build();
            return ResponseEntity.status(403).body(response);
        }

        authenticationService.registerUser(request);
        RegistrationResponse response = RegistrationResponse.builder()
                .message("User has successfully been created")
                .build();
        return ResponseEntity.ok(response);
    }

    @PostMapping("/sign")
    public ResponseEntity<LoginResponse> signIn(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authenticationService.loginUser(request));
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verify() {

        if (SecurityContextHolder.getContext().getAuthentication() != null &&
                SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            return ResponseEntity.ok("Token is valid");
        } else {
            return ResponseEntity.status(403).body("Invalid JWT token");
        }
    }
}
