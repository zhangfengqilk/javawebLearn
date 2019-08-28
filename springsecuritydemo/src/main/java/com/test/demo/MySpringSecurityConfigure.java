package com.test.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class MySpringSecurityConfigure extends WebSecurityConfigurerAdapter {
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("admin")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/hello" ).permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();
        /*http.authorizeRequests()
                //.anyRequest().authenticated() //任何请求,登录后可以访问
                .antMatchers("/hello").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/home")
                .permitAll() //登录页面用户任意访问
                .and()
                .logout().permitAll(); //注销行为任意访问*/

        // 范例
       /* http.authorizeRequests()
                //静态资源和一些所有人都能访问的请求
                .antMatchers("/css/**","/staic/**", "/js/**","/images/**").permitAll()
                .antMatchers("/", "/login","/session_expired").permitAll()
                //登录
                .and().formLogin()
                .loginPage("/login")
                .usernameParameter("userId")       //自己要使用的用户名字段
                .passwordParameter("password")     //密码字段
                .defaultSuccessUrl("/index")     //登陆成功后跳转的请求,要自己写一个controller转发
                .failureUrl("/loginAuthtictionFailed")  //验证失败后跳转的url
                //session管理
                .and().sessionManagement()
                .maximumSessions(1)                //系统中同一个账号的登陆数量限制
                .and().and()
                .logout()//登出
                .invalidateHttpSession(true)  //使session失效
                .clearAuthentication(true)    //清除证信息
                .and()
                .httpBasic();*/
    }


}
