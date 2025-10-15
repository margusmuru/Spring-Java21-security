package com.margusmuru.demo.service;

import com.margusmuru.demo.model.TokenResponse;
import com.margusmuru.demo.model.Users;
import com.margusmuru.demo.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final RedisKvService redisKvService;

    public Users registerUser(Users user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public TokenResponse verify(Users user) {
        var dbUser = userRepository.findByUsername(user.getUsername()).orElseThrow();
        user.setId(dbUser.getId());
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        if (authentication.isAuthenticated()) {
            return generateTokens(user);
        }
        throw new RuntimeException("User not verified");
    }

    private TokenResponse generateTokens(Users user) {
        var token = jwtService.generateToken(user.getUsername());

        var refreshToken = UUID.randomUUID().toString() + user.getUsername();
        var refreshTokenHash = jwtService.generateRefreshToken(refreshToken);
        refreshTokenService.save(user, refreshTokenHash);

        return TokenResponse.builder()
                .token(token)
                .refreshToken(refreshToken)
                .build();
    }

    public TokenResponse refresh(Users user, TokenResponse tokenResponse) {
        var refreshTokenHash = jwtService.generateRefreshToken(tokenResponse.getRefreshToken());
        if(!refreshTokenService.validate(user.getId(), refreshTokenHash)) {
            throw new RuntimeException("Invalid refresh token");
        }
        refreshTokenService.delete(tokenResponse.getRefreshToken());
        LocalDateTime tokenExpiration = jwtService.extractExpiration(tokenResponse.getToken());
        var key = "blacklist:" + tokenResponse.getToken();
        redisKvService.set(key, "true", Duration.between(LocalDateTime.now(), tokenExpiration));

        return generateTokens(user);
    }
}
