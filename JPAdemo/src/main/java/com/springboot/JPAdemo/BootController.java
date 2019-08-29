package com.springboot.JPAdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
public class BootController {
    @Autowired
    userReposery ur;
    @GetMapping("/user")
    public String user(){
        userinfo myuser=ur.getByName("admin");
        return myuser.getName();
    }
    @PostMapping("/user")
    public String adduser(@Validated userinfo u){
        /*userinfo a=new userinfo();
        a.setName("admin");
        a.setPassword("pss");*/
        ur.save(u);
        return "ok";
    }
}
