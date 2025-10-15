package com.margusmuru.demo.repo;

import com.margusmuru.demo.model.RefreshToken;
import com.margusmuru.demo.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {

    Optional<RefreshToken> findByTokenHash(String refreshTokenHash);

    @Modifying
    void deleteByTokenHash(String refreshTokenHash);

    void deleteByUserId(int userId);
}
