#  spring security 调试记录

### 1 	登录成功后如何跳转到指定页面

```
.authorizeRequests()
.antMatchers("/", "/home")
.permitAll()
.anyRequest()
.authenticated()
.and()
.formLogin()
.loginPage("/login")
.defaultSuccessUrl("/hello") //添加这句话就能转到指定的页面
.permitAll()
.and()
.logout()
.permitAll();
```

###  2 	登录成功后如何自定义返回json

```
public class MySuccessHandler implements AuthenticationSuccessHandler 
{    
	@Override    
	public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException 
	{       
        String json="{\"code\":0 ,\"desc\":\"成功\"}";
        httpServletResponse.setContentType("application/json;charset=UTF-8");
        httpServletResponse.getWriter().write(json);    
    }
}
```

​		首先实现AuthenticationSuccessHandler这个类的接口，然后在接口中的response中写入要返回的字符串

```
.authorizeRequests() 
//.mvcMatchers("/hello")
.hasRole("A") //
.mvcMatchers("/hello")
.hasRole("B") 
.antMatchers("/", "/home" )
.permitAll() 
.anyRequest()
.authenticated() 
.and() 
.formLogin() 
.loginPage("/login") 
//.successForwardUrl("/hello")//转发成功后的url 
//.failureForwardUrl("/hello")//转发失败后的URL 
//.failureUrl("/error")//重定向失败url 
//.defaultSuccessUrl("/hello")//重定向成功url 
.successHandler(new MySuccessHandler())//自定义成功处理器 
.failureHandler(new MyFailureHandler())//自定义失败的处理器 
.permitAll() .and() .logout() 
//.logoutUrl("/login") 
//.logoutSuccessUrl("")//重定向登出的url 
//.logoutSuccessHandler(new MylogoutSuccessHandler()) 
.permitAll(); 
//.and()
//.exceptionHandling() 
//.accessDeniedHandler(new MyAccessDeniHandler());
```

###  3   URL配置角色

###  4  从数据库查询用户名和密码

###  5  配置加密方法类

###  6   form表单提交不成功的原因

