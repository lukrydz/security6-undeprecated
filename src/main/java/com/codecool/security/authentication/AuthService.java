package com.codecool.security.authentication;

import com.codecool.security.config.JwtService;
import com.codecool.security.repository.UserRepository;
import com.codecool.security.user.RoleType;
import com.codecool.security.user.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository userRepository, JwtService jwtService, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public String register(RegisterRequest request) {
        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .email(request.email())
                .roleType(RoleType.USER)
                .build();
        userRepository.save(user);

        return jwtService.generateToken(user);
    }

    public String authenticate(AuthRequest authRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.username(), authRequest.password())
        );
        User user = userRepository.findByUsername(authRequest.username()).orElseThrow(() -> new UsernameNotFoundException("Username not found"));
        return jwtService.generateToken(user);
    }
}
