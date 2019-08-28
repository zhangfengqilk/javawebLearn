package com.tangcheng.app.rest.config;

import com.tangcheng.app.domain.exception.CaptchaException;
import com.tangcheng.app.rest.filter.LoginAuthenticationFilter;
import com.tangcheng.app.rest.security.LoginAuthenticationFailureHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.session.security.web.authentication.SpringSessionRememberMeServices;

import javax.security.auth.login.AccountExpiredException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by tang.cheng on 2016/12/12.
 */
@SuppressWarnings("SpringJavaAutowiringInspection")
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
@EnableWebSecurity
//As of Spring Security 4.0, @EnableWebMvcSecurity is deprecated. The replacement is @EnableWebSecurity which will determine adding the Spring MVC features based upon the classpath.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Autowired
//    FindByIndexNameSessionRepository<ExpiringSession> findByIndexNameSessionRepository;

    @Autowired
    private UserDetailsService userDetailsService;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
//        auth.inMemoryAuthentication()
//                .withUser("admin").password("admin").roles("ADMIN", "USER")
//                .and()
//                .withUser("user").password("user").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        LoginAuthenticationFilter loginAuthenticationFilter = new LoginAuthenticationFilter();
        loginAuthenticationFilter.setAuthenticationManager(authenticationManager());
        loginAuthenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        /**
         * o.s.security.web.FilterChainProxy        : /v1/mvc/valids at position 4 of 14 in additional filter chain; firing Filter: 'CsrfFilter'
         * o.s.security.web.csrf.CsrfFilter         : Invalid CSRF token found for http://localhost:8080/v1/mvc/valids
         * �˵㷵�صĴ�����Ϣ��
         * {
         *   "timestamp": 1543992032445,
         *   "status": 403,
         *   "error": "Forbidden",
         *   "message": "Invalid CSRF Token 'null' was found on the request parameter '_csrf' or header 'X-CSRF-TOKEN'.",
         *   "path": "/v1/mvc/valids"
         * }
         *
         * ������Ϣ��
         * Spring Security 4.0֮��������CSRF��Ĭ���ǿ��������ò�˵��CSRF��RESTful�����г�ͻ��CSRFĬ��֧�ֵķ����� GET|HEAD|TRACE|OPTIONS����֧��POST��
         * ԭ���ҵ��ˣ�spring Security 3Ĭ�Ϲر�csrf��Spring Security 4Ĭ��������csrf��?
         * ���������
         * ���������csrf���ɽ���security��csrf
         */
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET,
                        "/favicon.ico",
                        "/css/**", "/js/**",
                        "/captcha.jpg"
                ).permitAll()
                .antMatchers("/post/data/**").permitAll()
                .antMatchers("/user/**").hasRole("ADMIN")//Any URL that starts with "/admin/" will be restricted to users who have the role "ROLE_ADMIN". You will notice that since we are invoking the hasRole method we do not need to specify the "ROLE_" prefix.
                .antMatchers("/db/**").access("hasRole('ROLE_ADMIN')")
                .antMatchers("/flyway", "/tx/**", "/user/**", "/etag/**", "/test/**", "/v1/mvc/**").permitAll()
                .anyRequest().fullyAuthenticated()//Any URL that has not already been matched on only requires that the user be authenticated
                .and()
                .addFilterBefore(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin().permitAll().loginPage("/login").defaultSuccessUrl("/home")
                .and()
                .rememberMe()//��½����������һ����Ϊremember-me�Ĳ���
                .rememberMeServices(rememberMeServices())
                .tokenValiditySeconds(2419200)//four week 2419200s��Ĭ��������
                .key("cookbookKey")//�洢��cookies�а����û��������룬����ʱ���һ��˽Կ---��д��cookieǰ��������MD5 hash
                .and()
                .logout().invalidateHttpSession(true)//�û���HTTP session�������˳�ʱ��ʧЧ����һЩ�����£����Ǳ�Ҫ�ģ����û�ӵ��һ�����ﳵʱ��
                .clearAuthentication(true)
                .logoutSuccessUrl("/login")//�û����˳���Ҫ���ض��򵽵�URL��Ĭ��Ϊ/������ͨ��HttpServletResponse.redirect������
                .and()
                .headers().cacheControl().disable()
//                .and()
//                .sessionManagement()
//                .maximumSessions(2)
//                .sessionRegistry(sessionRegistry())
        ;
    }

    @Bean
    RememberMeServices rememberMeServices() {
        //https://docs.spring.io/spring-session/docs/1.3.1.RELEASE/reference/html5/#spring-security-rememberme
        SpringSessionRememberMeServices rememberMeServices = new SpringSessionRememberMeServices();
        // optionally customize
        rememberMeServices.setAlwaysRemember(true);
        return rememberMeServices;
    }

//    @Bean
//    SpringSessionBackedSessionRegistry sessionRegistry() {
//        return new SpringSessionBackedSessionRegistry(this.findByIndexNameSessionRepository);
//    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        ExceptionMappingAuthenticationFailureHandler failureHandler = new ExceptionMappingAuthenticationFailureHandler();
        Map<String, String> failureUrlMap = new HashMap<>();
        failureUrlMap.put(BadCredentialsException.class.getName(), LoginAuthenticationFailureHandler.PASS_ERROR_URL);
        failureUrlMap.put(CaptchaException.class.getName(), LoginAuthenticationFailureHandler.CODE_ERROR_URL);
        failureUrlMap.put(AccountExpiredException.class.getName(), LoginAuthenticationFailureHandler.EXPIRED_URL);
        failureUrlMap.put(LockedException.class.getName(), LoginAuthenticationFailureHandler.LOCKED_URL);
        failureUrlMap.put(DisabledException.class.getName(), LoginAuthenticationFailureHandler.DISABLED_URL);
        failureHandler.setExceptionMappings(failureUrlMap);
        return failureHandler;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //allow Swagger URL to be accessed without authentication
        web.ignoring().antMatchers( //"/v2/api-docs",//change to /swagger and custom the groupName
                "/swagger",// Resolve conflicts version number
                "/swagger-resources/configuration/ui",//������ȡ֧�ֵĶ���
                "/swagger-resources",//������ȡapi-docs��URI
                "/swagger-resources/configuration/security",//��ȫѡ��
                "/webjars/**",///swagger-ui.htmlʹ�õ�һЩ��Դ�ļ���webjarsĿ¼�¡�eg:http://localhost/webjars/springfox-swagger-ui/images/logo_small.png
                "/swagger-ui.html",
                "/h2/**" // h2/query.jsp?jsessionid=f2e1c5f5748414b8b4f8e844f74ef99d.The H2 database provides a browser-based console that Spring Boot can auto-configure for you.
        );
    }

}