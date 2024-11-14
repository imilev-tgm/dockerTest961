package com.gupta.userauthservice.service;
import com.gupta.userauthservice.entity.User;
import com.gupta.userauthservice.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service

@RequiredArgsConstructor
public class JwtService {

    private static final String SECRET_KEY = "sXmqIHFS7dGqVbYg0KxNOZgTUotyjG3ADhWlzrj2G3U=";

    public String extractUserEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Set<String> extractRoles(String token) {
        return extractClaim(token, claims -> {
            List<String> rolesList = claims.get("roles", List.class);
            return new HashSet<>(rolesList);
        });
    }


    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Methode um Claims aus dem token zu extrahieren
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(User user) {
        Map<String, Object> extraClaims = new HashMap<>();

        // Adding roles to claims
        extraClaims.put("roles", user.getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.toSet()));

        return generateToken(extraClaims, user);
    }

    private String generateToken(Map<String, Object> extraClaims, User user) {
        return Jwts.builder()
                .subject(user.getEmail())
                .claims(extraClaims)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // 24 hours
                .signWith(getSignInKey())
                .compact();
    }

    public boolean isTokenValid(String token, Optional<User> user) {
        final String email = extractUserEmail(token);
        return (email.equals(user.get().getEmail())) && !isTokenExpired(token);
    }

    public boolean isTokenValid(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
