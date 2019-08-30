package com.test.demo.config.security;

import com.test.demo.config.security.access.handler.JsonAccessDeniedHandler;
import com.test.demo.config.security.login.handler.JsonAuthenticationFailureHandler;
import com.test.demo.config.security.login.handler.JsonAuthenticationSuccessHandler;
import com.test.demo.config.security.logout.handler.JsonLogoutSuccessHandler;
import com.test.demo.config.security.user.password.FakePasswordEncoder;
import com.test.demo.config.security.user.service.FakeUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;


/**
 * @author lixinjie
 * @since 2018-11-05
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private AuthenticationProvider provider;  //注入我们自己的AuthenticationProvider

    @Autowired
    private DataSource dataSource;   //是在application.properites

    @Autowired
    private UserDetailsService userDetailsService;
    /**
     * 记住我功能的token存取器配置
     * @return
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // TODO Auto-generated method stub
        auth.authenticationProvider(provider);

//        auth
//        .inMemoryAuthentication()
//            .withUser("admin").password("123456").roles("USER")
//            .and()
//            .withUser("test").password("test123").roles("ADMIN");
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new FakeUserDetailsService();
    }
    /*@Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("admin")
                .password("admin")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }*/


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new FakePasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/rolea").hasRole("A")
                .mvcMatchers("/roleb").hasRole("B")
                //.antMatchers("/hello").permitAll()
                .anyRequest().authenticated()
                .anyRequest().access("@rbacService.hasPermission(request,authentication)")    //必须经过认证以后才能访问
                .and().formLogin()
                .loginPage("/login")
                //.loginProcessingUrl("/loginProcess")
                //.successForwardUrl("/example/success")//转发
                //.failureForwardUrl("/example/failure")//转发
                //.defaultSuccessUrl("/example/success")//重定向
                //.failureUrl("/example/failure")//重定向
                .successHandler(new JsonAuthenticationSuccessHandler())
                .failureHandler(new JsonAuthenticationFailureHandler())
                .permitAll()
                .and()
                .rememberMe()
                .rememberMeParameter("remember-me").userDetailsService(userDetailsService)
                .tokenRepository(persistentTokenRepository())
                .tokenValiditySeconds(60)
                .and().logout()
                .logoutUrl("/logoutProcess")
                //.logoutSuccessUrl("/example/logout")//重定向
                .logoutSuccessHandler(new JsonLogoutSuccessHandler())
                .permitAll()
                .and().exceptionHandling()
                //.accessDeniedPage("/example/deny");//转发
                .accessDeniedHandler(new JsonAccessDeniedHandler())
                .and().csrf().disable();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.debug(true)
                .ignoring()
                .antMatchers("/images/**", "/js/**", "/css/**");
    }
}
