package com.margusmuru.demo.controller;

import com.margusmuru.demo.model.TokenResponse;
import com.margusmuru.demo.model.UserPrincipal;
import com.margusmuru.demo.model.Users;
import com.margusmuru.demo.service.JwtService;
import com.margusmuru.demo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final JwtService jwtService;

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
        // validate that included token belongs to user
        Users user = ((UserPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUser();
        String authHeader = request.getHeader("Authorization");
        String token = authHeader.substring(7);
        String username = jwtService.extractUsername(token);
        if (!user.getUsername().equals(username) || !token.equals(tokenResponse.getToken())) {
            throw new RuntimeException("Mismatch");
        }
        return userService.refresh(user, tokenResponse);
    }
}
