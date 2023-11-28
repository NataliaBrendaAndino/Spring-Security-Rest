package com.brenA.demojwt.seguridad.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

//no nos olvidemos de esta anotation
@Service
public class JwtService {

    private static final String SECRET_KEY = "586E3272357538782F413F4428472B4B6250655368566B597033733676397924";

    // este mètodo es el que invocaremos en el AuthService
    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    // este crea el token:
    // especifica todas las partes del token (encabezado, carga útil y firma)
    private String getToken(Map<String, Object> extraClaims, UserDetails user) {
        // construimos el jwt
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                // establece la fecha de emisión del token
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                // firma el token utilizando una clave secreta y un algoritmo de firmas
                .signWith(getKey(), SignatureAlgorithm.HS256)
                // toma todo lo que configuramos anteriormente
                // y lo compacta en una cadena de texto que se puede
                // enviar y recibir mediante encabezados HTTP
                .compact();
    }

    private Key getKey() {
        // convierte la SECRET_KEY en un arreglo de bytes
        // utilizando la decodificación BASE64.
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // construye una clave HMAC con el arreglo de bytes
        // hmacShaKeyFor crea una nueva instancia de la SECRET_KEY
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
