package com.margusmuru.demo.model;


import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Data;

@Data
@Entity
public class Users {
    @Id
    private int id;
    private String username;
    private String password;
}
