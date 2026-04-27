package com.challenge.AuthApi.controller;

import com.challenge.AuthApi.dto.AuthResponse;
import com.challenge.AuthApi.dto.LoginRequest;
import com.challenge.AuthApi.dto.RegisterRequest;
import com.challenge.AuthApi.dto.UserResponse;
import com.challenge.AuthApi.entity.User;
import com.challenge.AuthApi.service.UserService;
import com.challenge.AuthApi.security.JwtService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/auth" )
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;

    public AuthController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        User user = new User();
        user.setEmail(request.email());
        user.setSenha(request.senha());
        user.setNome(request.nome());
        user.setRole(request.role());

        User savedUser = userService.createUser(user);

        UserResponse response = new UserResponse(
                savedUser.getId(),
                savedUser.getEmail(),
                savedUser.getRole()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            User user = userService.authenticate(
                    request.email(),
                    request.senha()
            );

            String token = jwtService.generateToken(user.getEmail(), user.getRole());

            return ResponseEntity.ok(new AuthResponse(
                    token,
                    user.getEmail(),
                    user.getRole()
            ));

        } catch (AuthenticationException e) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas");
        } catch (ResponseStatusException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getReason());
        }
    }
}