package com.codecool.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/hello")
public class SomeResourceController {

    @GetMapping
    @PreAuthorize("hasAuthority('USER')")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello :)");
    }
}
