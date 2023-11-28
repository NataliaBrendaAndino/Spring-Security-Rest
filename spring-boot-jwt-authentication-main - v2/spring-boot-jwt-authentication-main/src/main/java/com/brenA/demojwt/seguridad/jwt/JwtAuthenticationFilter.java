package com.brenA.demojwt.seguridad.jwt;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.StringUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

//IoC: delegamos a Spring el ciclo de vida de este componente
//que se ocupará de manipular los tokens
@Component
@RequiredArgsConstructor
// extendemos de esta clase para personalizar el filtro,
// para que el filtro se ejecute solo una vez por cada solicitud http
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // Nos pide sobreescribir este método
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String token = getTokenFromRequest(request);

        // si es nulo, delegamos el control a la cadena de filtros
        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // si no es nulo, que siga su ruta
        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Clase de SpringUtils para trabajar con String
        // está buscando que, de todo el Header, vaya al auth,
        // y que el authHeader contenga "Bearer", que es como inicia todo JWT
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

}
