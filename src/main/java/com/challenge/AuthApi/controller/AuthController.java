package com.challenge.AuthApi.controller;

import com.challenge.AuthApi.dto.AuthResponse;
import com.challenge.AuthApi.dto.LoginRequest;
import com.challenge.AuthApi.dto.RegisterRequest;
import com.challenge.AuthApi.dto.UserResponse;
import com.challenge.AuthApi.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService service;

    public AuthController(UserService service) {
        this.service = service;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @Valid @RequestBody RegisterRequest request) {

        UserResponse response = service.register(request);
        return ResponseEntity.status(201).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request) {

        AuthResponse response = service.login(request);
        return ResponseEntity.ok(response);
    }
}