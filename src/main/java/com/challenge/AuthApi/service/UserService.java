package com.challenge.AuthApi.service;

import com.challenge.AuthApi.entity.User;
import com.challenge.AuthApi.repository.UserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    //  Criar usuário
    public User createUser(User user) {

        Optional<User> existing = userRepository.findByEmail(user.getEmail());
        if (existing.isPresent()) {
            throw new RuntimeException("User already exists with this email");
        }

        // criptografa senha
        String encodedPassword = passwordEncoder.encode(user.getSenha());
        user.setSenha(encodedPassword);

        // define role padrão
        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("USER");
        }

        return userRepository.save(user);
    }

    // Autenticação (login)
    public User authenticate(String email, String password) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(password, user.getSenha())) {
            throw new RuntimeException("Invalid password");
        }

        return user;
    }

    //  Buscar por email
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    //  Listar todos
    public Iterable<User> findAll() {
        return userRepository.findAll();
    }

    //  Deletar
    public void delete(Long id) {
        if (!userRepository.existsById(id)) {
            throw new RuntimeException("User not found");
        }
        userRepository.deleteById(id);
    }
}