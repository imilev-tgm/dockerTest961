package com.gupta.userauthservice.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gupta.userauthservice.entity.User;
import com.gupta.userauthservice.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Service
@RequiredArgsConstructor
public class InitializationService {

    private static final Logger logger = LoggerFactory.getLogger(InitializationService.class);

    private final PasswordEncoder passwordEncoder;

    private final UserRepository repository;

    @PostConstruct
    public void loadUsersFromJson() {
        ObjectMapper mapper = new ObjectMapper();
        TypeReference<List<User>> typeReference = new TypeReference<>() {};
        InputStream inputStream = getClass().getResourceAsStream("/users.json");
        try {
            List<User> users = mapper.readValue(inputStream, typeReference);
            users.forEach(user -> {
                user.setPassword(passwordEncoder.encode(user.getPassword())); // Passwort verschlüsseln
                repository.save(user);
            });
            logger.info("Users successfully loaded and saved in the database.");
        } catch (IOException e) {
            logger.error("Unable to load users: " + e.getMessage());
        }
    }
}
