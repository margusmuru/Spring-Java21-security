package com.margusmuru.demo.service;

import com.margusmuru.demo.model.Users;
import com.margusmuru.demo.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public Users registerUser(Users user) {
        return userRepository.save(user);
    }
}
