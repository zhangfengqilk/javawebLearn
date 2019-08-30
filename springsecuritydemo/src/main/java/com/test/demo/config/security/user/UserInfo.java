/*
package com.test.demo.config.security.user;


import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;


import java.security.Timestamp;
import java.util.ArrayList;
import java.util.List;


public class UserInfo extends User {
    private Long id;
    private String username;
    private String password;
    private String nickname;
    private boolean enabled;
    private List<MyRole> roles;
    private String email;
    private String userface;
    private Timestamp regTime;

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() { // 帐户是否过期
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() { // 帐户是否被冻结
        return true;
    }

    // 帐户密码是否过期，一般有的密码要求性高的系统会使用到，比较每隔一段时间就要求用户重置密码
    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {  // 帐号是否可用
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    @JsonIgnore
    public List<GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (MyRole role : roles) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    //....getter setter
}*/
