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

    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    private String getToken(Map<String, Object> extraClaims, UserDetails user) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // recibe un token como argumento, del cual extraerá el username
    public String getUsernameFromToken(String token) {
        // el método getClaim está definido posteriormente
        // el segundo argumento corresponde a la sintaxis de
        // Function y está diciendo: de todas las Claims, la que quiero es la de Subject
        // (es decir, el username del token)
        return getClaim(token, Claims::getSubject);
    }

    // para determinar si es válido, debemos saber si expiró o no
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private Claims getAllClaims(String token) {
        return Jwts
                // crea un parser de JWT, que extrae la información contenida en el token, como
                // los claims.
                .parserBuilder()
                // verifica la llave con la estretegia del método getKey
                .setSigningKey(getKey())
                .build()
                // Parsea el token JWT y verifica su firma
                .parseClaimsJws(token)
                // Obtiene el cuerpo del token, que contiene los claims
                .getBody();
    }

    // el método retorna un genérico
    // recibe por parámetro un reclamo: cuál? El que necesitemos, está definido como
    // T
    // sintaxis de Function<lo_que_recibe, lo_que_devuelve> nombre_de_la_function
    // objetivo del método: proporciona una forma genérica de extraer información de
    // un token JWT
    public <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
        // instancia un Claims de io.jsonwebtoken.Claims;
        // le asigna el valor de todos los Claims asociados en el método detAllClaims
        final Claims claims = getAllClaims(token);
        // retorna una Function, cuyo primer valor es claims (la reciente instancia de
        // Claims)
        // y el segundo valor dependerá de lo que se le pida cuando se la invoque
        return claimsResolver.apply(claims);
    }

    private Date getExpiration(String token) {
        return getClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token) {
        // compara la fecha de expiración obtenida del token con la fecha y hora
        // actuales
        return getExpiration(token).before(new Date());
    }

}
