package com.brenA.demojwt.seguridad.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.brenA.demojwt.seguridad.jwt.JwtService;
import com.brenA.demojwt.seguridad.user.Role;
import com.brenA.demojwt.seguridad.user.User;
import com.brenA.demojwt.seguridad.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    // por el momento hacemos un servicio para registrar
    public AuthResponse register(RegisterRequest request) {
        User user = User.builder()
                // construimos un usuario con los valores que le llegaron a RegisterRequest
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstname(request.getFirstname())
                .lastname(request.lastname)
                .country(request.getCountry())
                .role(Role.USER)
                .build();

        // guardamos al usuario
        userRepository.save(user);

        // me tiene que enviar un token
        return AuthResponse.builder()
                // nos falta construir el objeto token que vamos a mandar aquí
                // eso lo haremos en JwtService
                .token(null)
                // .token(jwtService.getToken(user))
                .build();

    }

}
