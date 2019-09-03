package com.myproject.swaggerproject;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class SwaggerprojectApplication {

    public static void main(String[] args) {
        SpringApplication.run(SwaggerprojectApplication.class, args);
    }

}
