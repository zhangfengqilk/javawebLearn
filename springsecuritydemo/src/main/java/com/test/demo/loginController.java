package com.test.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class loginController {
    @GetMapping("/hello")
     public Object login()
    {
        return "hello world";
    }
}
