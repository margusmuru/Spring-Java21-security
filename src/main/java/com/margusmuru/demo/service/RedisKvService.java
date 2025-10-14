package com.margusmuru.demo.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RedisKvService {

    private final StringRedisTemplate redis;

    public void set(String key, String value) {
        redis.opsForValue().set(key, value);
    }

    public void set(String key, String value, Duration ttl) {
        ValueOperations<String, String> ops = redis.opsForValue();
        ops.set(key, value, ttl);
    }

    public String get(String key) {
        return redis.opsForValue().get(key);
    }

    public Boolean delete(String key) {
        return redis.delete(key);
    }

    public Boolean exists(String key) {
        return redis.hasKey(key);
    }
}
