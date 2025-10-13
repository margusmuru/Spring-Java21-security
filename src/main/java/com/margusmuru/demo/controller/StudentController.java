package com.margusmuru.demo.controller;

import com.margusmuru.demo.model.Student;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StudentController {

  private final List<Student> students = new ArrayList<>(List.of(
      new Student(1, "Alice", 85),
      new Student(2, "Bob", 90),
      new Student(3, "Charlie", 78)
  ));

  @GetMapping("/students")
  public List<Student> getStudents() {
    return students;
  }

  @GetMapping("/csrf-token")
  public CsrfToken getCsrfToken(HttpServletRequest request) {
    return (CsrfToken) request.getAttribute("_csrf");
  }

  @PostMapping("/students")
  public Student addStudent(@RequestBody Student student) {
    students.add(student);
    return student;
  }

}
