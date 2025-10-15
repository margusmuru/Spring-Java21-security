package com.margusmuru.demo.service;

import com.margusmuru.demo.model.RefreshToken;
import com.margusmuru.demo.model.Users;
import com.margusmuru.demo.repo.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

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

    public Optional<RefreshToken> getRefreshTokenByHash(String refreshTokenHash) {
        return refreshTokenRepository.findByTokenHash(refreshTokenHash);
    }

    @Transactional
    public void deleteByHash(String refreshTokenHash) {
        refreshTokenRepository.deleteByTokenHash(refreshTokenHash);
    }

    @Transactional
    public void deleteByUserId(int id) {
        refreshTokenRepository.deleteByUserId(id);
    }
}
