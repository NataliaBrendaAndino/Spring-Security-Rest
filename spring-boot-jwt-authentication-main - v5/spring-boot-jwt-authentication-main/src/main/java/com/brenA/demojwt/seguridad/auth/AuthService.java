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
    // declaramos un AuthenticarionManager para administrar los filtros del login
    private final AuthenticationManager authenticationManager;

    // recibimos por parámetro los datos del login
    public AuthResponse login(LoginRequest request) {
        // para autenticar el usuario, usamos este método authenticate
        // instanciamos un nuevo UsernamePasswordAuthenticationToken con el nombre y
        // contraseña procesado en la solicitud,
        // este objeto trabajará en conjunto con el AuthenticationProvider para validar
        // la solicitud
        // en caso de éxito, avanza hacia la generación del token
        authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        // para generar el token, Security precisa trabajar con el UserDetails,
        // que tiene detalles de la sesión que también pasan por un filtro de seguridad
        UserDetails user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        String token = jwtService.getToken(user);
        return AuthResponse.builder()
                .token(token)
                .build();

    }

    public AuthResponse register(RegisterRequest request) {
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstname(request.getFirstname())
                .lastname(request.lastname)
                .country(request.getCountry())
                .role(Role.USER)
                .build();

        userRepository.save(user);

        return AuthResponse.builder()
                .token(jwtService.getToken(user))
                .build();

    }

}
