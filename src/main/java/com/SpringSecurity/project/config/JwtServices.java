package com.SpringSecurity.project.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtServices {

    @Value("${spring.application.security.jwt.secret-key}")
    //Secret key
    private String secretKey;

    @Value("${spring.application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${spring.application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    //extract username from the jwt
    public String extractUserName(String token) {
        System.out.println("extractUserName -------------------");
        return extractClaim(token,Claims::getSubject);
    }
    //extract data from the jwt
    public <T>  T extractClaim(String token, Function<Claims, T> claimResolver){
        System.out.println("extractClaim --------------------");
        final Claims claims = extractAllClaims(token);

        return claimResolver.apply(claims);
    }


    //generate jwt with the username
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }
    //generate jwt with the username & roles
    public String generateToken(Map<String, Objects> extraClaims,
                                UserDetails userDetails
                                ){
        return buildJwtToken(extraClaims, userDetails, jwtExpiration);
    }
    public String generateRefreshToken(UserDetails userDetails
    ){
        return buildJwtToken(new HashMap<>(), userDetails, refreshExpiration);
    }
    private String buildJwtToken(Map<String, Objects> extraClaims,
                                 UserDetails userDetails,
                                 long expiration){
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() +expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }
    //validating the token
    public boolean isTokenVaild(String token, UserDetails userDetails){
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    //validating the expiration
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());

    }


    //extract expiration from the jwt
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //extract all data  from the jwt
    private Claims extractAllClaims(String token){

        System.out.println("extractAllClaims --------------------");

        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //encoding the secret key
    //encoding the secret key
    private Key getSignInKey() {
        System.out.println("getSignInKey --------------------");

        byte[] keyBytes = Decoders.BASE64.decode(secretKey);

        return Keys.hmacShaKeyFor(keyBytes);
    }
}
