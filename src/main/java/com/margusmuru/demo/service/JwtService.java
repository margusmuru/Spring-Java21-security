package com.margusmuru.demo.service;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    // must be at least 256 bits for HS256
    // generate secret: https://generate-random.org/encryption-keys
    // validate generated token: https://www.jwt.io/
    private final String SECRET_KEY = "ba0a6bcb9c5c194f7a834d47579e6f85eeb0dbb3fcb4d0cec79ad7a320f5e3d0";

    public String generateToken(String username) {

        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 5)) // 5 min
                .and()
                .signWith(getKey())
                .compact();

    }

    public String generateRefreshTokenHash(String token) {
        try {
            SecretKey key = getKey();
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] hashBytes = mac.doFinal(token.getBytes());
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing refresh token", e);
        }
    }

    private SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (ClaimJwtException e) {
            return null;
        }
    }

    public LocalDateTime extractExpiration(String token) {
        try {
            var date = extractClaim(token, Claims::getExpiration);
            return LocalDateTime.ofInstant(date.toInstant(), java.time.ZoneId.systemDefault());
        } catch (ClaimJwtException e) {
            return LocalDateTime.MIN;
        }
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String userName = extractUsername(token);
            return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (ClaimJwtException e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        try {
            return extractClaim(token, Claims::getExpiration).before(new Date());
        } catch (ClaimJwtException e) {
            return true;
        }
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
