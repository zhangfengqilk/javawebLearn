package com.springboot.JPAdemo;

import org.springframework.data.jpa.repository.JpaRepository;

public interface userReposery  extends JpaRepository<userinfo,Long> {
    userinfo getByName(String name);

    @Override
    <S extends userinfo> S save(S s);
}
