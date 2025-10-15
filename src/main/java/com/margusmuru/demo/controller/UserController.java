package com.margusmuru.demo.controller;

import com.margusmuru.demo.model.TokenResponse;
import com.margusmuru.demo.model.UserPrincipal;
import com.margusmuru.demo.model.Users;
import com.margusmuru.demo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    public Users register(@RequestBody Users user) {
        return userService.registerUser(user);
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody Users user) {
        return userService.verify(user);
    }

    @PostMapping("/refresh-token")
    public TokenResponse refreshToken(HttpServletRequest request,
                                      @RequestBody TokenResponse tokenResponse) {
        String authHeader = request.getHeader("Authorization");
        String token = authHeader != null ? authHeader.substring(7) : null;
        return userService.refreshTokens(tokenResponse.getRefreshToken(), token);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        Users user = ((UserPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUser();
        String authHeader = request.getHeader("Authorization");
        String token = authHeader.substring(7);
        userService.invalidateJwt(token);
        userService.invalidateRefreshToken(user);
        return ResponseEntity.noContent().build();
    }
}
