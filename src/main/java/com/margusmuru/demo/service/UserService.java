package com.margusmuru.demo.service;

import com.margusmuru.demo.model.LoginResponse;
import com.margusmuru.demo.model.Users;
import com.margusmuru.demo.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public Users registerUser(Users user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public LoginResponse verify(Users user) {
        var dbUser = userRepository.findByUsername(user.getUsername()).orElseThrow();
        user.setId(dbUser.getId());
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        if (authentication.isAuthenticated()) {
            var token = jwtService.generateToken(user.getUsername());
            //generate refresh token and save it to db
            var refreshToken = UUID.randomUUID().toString() + user.getUsername();
            var refreshTokenHash = jwtService.generateRefreshToken(refreshToken);
            refreshTokenService.save(user, refreshTokenHash);
            // return jwt and refresh token
            return LoginResponse.builder()
                    .token(token)
                    .refreshToken(refreshToken)
                    .build();
        }
        throw new RuntimeException("User not verified");
    }
}
