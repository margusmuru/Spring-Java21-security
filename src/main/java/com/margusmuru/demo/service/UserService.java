package com.margusmuru.demo.service;

import com.margusmuru.demo.model.RefreshToken;
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
import java.util.Optional;
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
        var refreshTokenHash = jwtService.generateRefreshTokenHash(refreshToken);
        refreshTokenService.save(user, refreshTokenHash);

        return TokenResponse.builder()
                .token(token)
                .refreshToken(refreshToken)
                .build();
    }

    public TokenResponse refreshTokens(String refreshToken, String jwtToken) {
        var refreshTokenHash = jwtService.generateRefreshTokenHash(refreshToken);
        Optional<RefreshToken> existingToken = refreshTokenService.getRefreshTokenByHash(refreshTokenHash);
        if (existingToken.isEmpty() || existingToken.get().getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh token not found or expired");
        }
        refreshTokenService.deleteByHash(refreshTokenHash);
        Users user = userRepository.findById(existingToken.get().getUserId()).orElseThrow();

        TokenResponse tokens = generateTokens(user);

        invalidateJwt(jwtToken);
        return tokens;
    }

    public void invalidateJwt(String jwtToken) {
        if (jwtToken == null) {
            return;
        }
        var key = "blacklist:" + jwtToken;
        LocalDateTime tokenExpiration = jwtService.extractExpiration(jwtToken);
        if (tokenExpiration.isBefore(LocalDateTime.now())) {
            return;
        }
        redisKvService.set(key, "true", Duration.between(LocalDateTime.now(), tokenExpiration));
    }

    public void invalidateRefreshToken(Users user) {
        refreshTokenService.deleteByUserId(user.getId());
    }
}
