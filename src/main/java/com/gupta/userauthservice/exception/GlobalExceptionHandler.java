package com.gupta.userauthservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;

@ControllerAdvice
public class GlobalExceptionHandler<T> {

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<T> handleExpiredJwtException(ExpiredJwtException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body((T) "JWT token has expired");
    }

    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<T> handleSignatureException(SignatureException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body((T) "JWT token signature is invalid");
    }
}
