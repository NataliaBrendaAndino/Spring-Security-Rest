package com.brenA.demojwt.seguridad.jwt;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.StringUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // agregamos los servicios
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String token = getTokenFromRequest(request);
        // agregamos este atributo
        final String username;
        // tendremos que crear este método en el servicio jwtService
        username = jwtService.getUsernameFromToken(token);

        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // validamos username
        // si es distinto de nulo y su autenticación no la encuentra en el contexto
        // actual de la sesión...
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // entonces, que la vaya a buscar a la DB
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // si el token es válido (no ha caducado o la firma es válida) para ESTE usuario
            if (jwtService.isTokenValid(token, userDetails)) {
                // si es válido, creame un usuarioAutenticado
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        // en JWT no se necesita la contraseña después de la autenticación inicial.
                        null,
                        // que cargue los roles asociados
                        userDetails.getAuthorities());

                // detalles web adicionales, en este caso del HttpServletRequest
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // el usuario representado por este token ahora está autenticado y
                // puede acceder a los recursos protegidos
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }
        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

}
