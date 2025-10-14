package com.margusmuru.demo.repo;

import com.margusmuru.demo.model.RefreshToken;
import com.margusmuru.demo.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {

}
