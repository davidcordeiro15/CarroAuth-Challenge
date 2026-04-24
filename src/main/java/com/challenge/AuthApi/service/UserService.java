package com.challenge.AuthApi.service;

import com.challenge.AuthApi.dto.AuthResponse;
import com.challenge.AuthApi.dto.LoginRequest;
import com.challenge.AuthApi.dto.RegisterRequest;
import com.challenge.AuthApi.dto.UserResponse;
import com.challenge.AuthApi.entity.User;
import com.challenge.AuthApi.repository.UserRepository;
import com.challenge.AuthApi.security.JwtService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository repository;
    private final BCryptPasswordEncoder encoder;
    private JwtService jwtService;
    public UserService(UserRepository repository, BCryptPasswordEncoder encoder) {
        this.repository = repository;
        this.encoder = encoder;
    }

    public UserResponse register(RegisterRequest request) {

        repository.findByEmail(request.email())
                .ifPresent(u -> {
                    throw new RuntimeException("Email já cadastrado");
                });

        User user = User.builder()
                .nome(request.nome())
                .email(request.email())
                .senha(encoder.encode(request.senha()))
                .role("USER")
                .build();

        repository.save(user);

        return new UserResponse(
                user.getId(),
                user.getNome(),
                user.getEmail(),
                user.getRole()
        );
    }

    public AuthResponse login(LoginRequest request) {

        User user = repository.findByEmail(request.email())
                .orElseThrow(() -> new RuntimeException("Credenciais inválidas"));

        if (!encoder.matches(request.senha(), user.getSenha())) {
            throw new RuntimeException("Credenciais inválidas");
        }

        String token = jwtService.generateToken(user.getEmail(), user.getRole());

        return new AuthResponse(token);
    }
}