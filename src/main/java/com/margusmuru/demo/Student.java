package com.margusmuru.demo;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Student {
  private int id;
  private String name;
  private int marks;

}
