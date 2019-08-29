package com.springboot.JPAdemo;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Data
public class userinfo {
    @Id
    @GeneratedValue
    private long id;
    String name;
    String password;

}
