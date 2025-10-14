package com.margusmuru.demo.controller;

import com.margusmuru.demo.service.RedisKvService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/kv")
@RequiredArgsConstructor
public class KvController {

    private final RedisKvService service;

    @PutMapping("/{key}")
    public ResponseEntity<Void> put(@PathVariable String key,
                                    @RequestParam(required = false) Long ttlSeconds,
                                    @RequestBody String value
    ) {
        if (ttlSeconds != null) {
            service.set(key, value, Duration.ofSeconds(ttlSeconds));
        } else {
            service.set(key, value);
        }
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{key}")
    public ResponseEntity<?> get(@PathVariable String key) {
        String val = service.get(key);
        return (val == null) ? ResponseEntity.notFound().build()
                : ResponseEntity.ok(Map.of("key", key, "value", val));
    }

    @DeleteMapping("/{key}")
    public ResponseEntity<?> delete(@PathVariable String key) {
        boolean deleted = Boolean.TRUE.equals(service.delete(key));
        return deleted ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    @RequestMapping(value = "/{key}", method = RequestMethod.HEAD)
    public ResponseEntity<Void> exists(@PathVariable String key) {
        return Boolean.TRUE.equals(service.exists(key))
                ? ResponseEntity.ok().build()
                : ResponseEntity.notFound().build();
    }
}
