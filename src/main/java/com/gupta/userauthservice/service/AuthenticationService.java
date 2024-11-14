package com.gupta.userauthservice.service;

import com.gupta.userauthservice.dto.*;
import com.gupta.userauthservice.dto.RegistrationRequest;
import com.gupta.userauthservice.entity.User;
import com.gupta.userauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;


    public VerificationResponse registerUser(RegistrationRequest request) {
        String encodedPassword = passwordEncoder.encode(request.getPassword()); //verschlüssele Passwort

        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(encodedPassword)
                .roles(request.getRoles())
                .build();

        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return VerificationResponse.builder().roles(user.getRoles()).build();
    }

    public LoginResponse loginUser(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return LoginResponse.builder()
                .token(jwtToken)
                .message("Successfully logged in")
                .build();
    }

    public VerificationResponse verify(String token) {
        boolean isTokenValid = jwtService.isTokenValid(token);

        if (!isTokenValid) {
            throw new SecurityException("Invalid JWT token");
        }

        String email = jwtService.extractUserEmail(token);
        var user = userRepository.findByEmail(email).orElseThrow();

        return VerificationResponse.builder()
                .roles(user.getRoles())
                .build();
    }
}
