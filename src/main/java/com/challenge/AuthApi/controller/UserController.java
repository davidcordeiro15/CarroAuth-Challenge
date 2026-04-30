package com.challenge.AuthApi.controller;


import com.challenge.AuthApi.entity.User;
import com.challenge.AuthApi.service.UserService;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // LISTAR USUÁRIOS
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping
    //@PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = (List<User>) userService.findAll();
        return ResponseEntity.ok(users);
    }

    //  ATUALIZAR USUÁRIO
    @SecurityRequirement(name = "bearerAuth")
    @PutMapping("/{id}")
    public ResponseEntity<User> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody User updatedUser) {

        User user = userService.update(id, updatedUser);
        return ResponseEntity.ok(user);
    }

    //  DELETAR USUÁRIO
    @SecurityRequirement(name = "bearerAuth")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {

        userService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
