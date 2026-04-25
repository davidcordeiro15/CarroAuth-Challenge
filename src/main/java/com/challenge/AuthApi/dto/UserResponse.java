package com.challenge.AuthApi.dto;

public record UserResponse(
        Long id,
        String nome,
        String email
) {}