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

###  7   JPA操作数据库
JPA操作数据库需要先引入jpa的依赖，可以在建工程时直接引入，也可以在pom.xml中手动引入

		<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
		<dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>

然后新建一个类，用来和数据库的表进行映射,加注解@Entity


    @Entity
    @Data
    public class userinfo {
	    @Id
	    @GeneratedValue
	    private long id;
	    String name;
	    String password;    
    }


然后新建一个接口类，继承JpaRepository<userinfo,Long> ，其中有两个参数，第一个写这个接口类对应的数据类，就是刚才我们建的表类型，第二个参数就是主键类型，然后借助IDE自动生成一些接口

    public interface userReposery  extends JpaRepository<userinfo,Long> {    
		//声明get函数
    	userinfo getByName(String name);  
  		//声明sava函数
	    @Override
	    <S extends userinfo> S save(S s);
    }

接下来写controller函数接口

	@Autowired
    userReposery ur;
 	//查询
    @GetMapping("/user")
    public String user(){
        userinfo myuser=ur.getByName("admin");
        return myuser.getName();
    }
	//写入
    @PostMapping("/user")
    public String adduser(@Validated userinfo u){
        /*userinfo a=new userinfo();
        a.setName("admin");
        a.setPassword("pss");*/
        ur.save(u);
        return "ok";
    }
POSTMAN写测试接口
![](JPApost.jpg)
