package com.margusmuru.demo.service;

import com.margusmuru.demo.model.RefreshToken;
import com.margusmuru.demo.model.Users;
import com.margusmuru.demo.repo.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshToken save(Users users, String refreshTokenHash) {
        var token = RefreshToken.builder()
                .userId(users.getId())
                .tokenHash(refreshTokenHash)
                .created(LocalDateTime.now())
                .expiryDate(LocalDateTime.now().plusHours(1))
                        .build();
        return refreshTokenRepository.save(token);
    }

    public boolean validate(int userId, String refreshTokenHash) {
        var tokenOpt = refreshTokenRepository.findByTokenHash(refreshTokenHash);
        if (tokenOpt.isEmpty()) {
            return false;
        }
        var token = tokenOpt.get();
        if(token.getUserId() != userId) {
            return false;
        }
        return !token.getExpiryDate().isBefore(LocalDateTime.now());
    }

    public void delete(String refreshTokenHash) {
        refreshTokenRepository.deleteByTokenHash(refreshTokenHash);
    }
}
