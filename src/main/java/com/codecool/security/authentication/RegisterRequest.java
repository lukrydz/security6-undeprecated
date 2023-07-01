package com.codecool.security.authentication;

public record RegisterRequest(String username, String password, String email) {
}
