package com.challenge.AuthApi.controller;

import com.challenge.AuthApi.dto.AuthResponse;
import com.challenge.AuthApi.dto.LoginRequest;
import com.challenge.AuthApi.dto.RegisterRequest;
import com.challenge.AuthApi.dto.UserResponse;
import com.challenge.AuthApi.entity.User;
import com.challenge.AuthApi.service.UserService;
import com.challenge.AuthApi.security.JwtService;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;

    public AuthController(UserService userService,
                          JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    // 🔹 REGISTER
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @Valid @RequestBody RegisterRequest request) {

        User user = new User();
        user.setEmail(request.email());
        user.setSenha(request.senha());

        User savedUser = userService.createUser(user);

        UserResponse response = new UserResponse(
                savedUser.getId(),
                savedUser.getEmail(),
                savedUser.getRole()
        );

        return ResponseEntity.status(201).body(response);
    }

    // 🔹 LOGIN
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request) {

        User user = userService.authenticate(
                request.email(),
                request.senha()
        );

        String token = jwtService.generateToken(user.getEmail(), user.getRole());

        AuthResponse response = new AuthResponse(
                token,
                user.getEmail(),
                user.getRole()
        );

        return ResponseEntity.ok(response);
    }
}