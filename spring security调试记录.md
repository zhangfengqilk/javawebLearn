#   spring security 调试记录

## 1 	登录成功后如何跳转到指定页面

```java
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

##  2 	登录成功后如何自定义返回json

```java
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

```java
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

##  3   URL配置角色

##  4  从数据库查询用户名和密码

##  5  配置加密方法类

##  6   form表单提交不成功的原因

##  7   JPA操作数据库
JPA操作数据库需要先引入jpa的依赖，可以在建工程时直接引入，也可以在pom.xml中手动引入

```xml
	<dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
	<dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <scope>runtime</scope>
    </dependency>
```

然后新建一个类，用来和数据库的表进行映射,加注解@Entity


```java
@Entity
@Data
public class userinfo {
    @Id
    @GeneratedValue
    private long id;
    String name;
    String password;    
}
```


然后新建一个接口类，继承JpaRepository<userinfo,Long> ，其中有两个参数，第一个写这个接口类对应的数据类，就是刚才我们建的表类型，第二个参数就是主键类型，然后借助IDE自动生成一些接口

```java
public interface userReposery  extends JpaRepository<userinfo,Long> {    
	//声明get函数
	userinfo getByName(String name);  
	//声明sava函数
	@Override
	<S extends userinfo> S save(S s);
}
```


接下来写controller函数接口

```java
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
```

POSTMAN写测试接口
![](JPApost.jpg)


##  7   JPA方言问题
​		上面的例子是在建工程时就引入了JPA，所以没有出现方言问题
后来我在以前的项目中试图引入JPA，然后按上面的步骤做了一遍，发现并不能自动生成表，然后查找问题发现和两个地方的配置有关

  JPA的配置在配置文件中需要加入下面几个配置，spring.jpa.hibernate.ddl-auto.update=true这个属性是自动建表的
然后发现自动建表失败，报错为：
> Error executing DDL via JDBC Statement

然后发现JPA涉及到数据库的方言问题spring.jpa.database-platform=org.hibernate.dialect.MySQL5InnoDBDialect
这个就是JPA的方言。

```yml
	spring:
  		jpa:
		    database-platform: org.hibernate.dialect.MySQL5InnoDBDialect
		    show-sql: true
		    hibernate:
		      ddl-auto: update 	
  		#数据库设置
  		datasource:
		    username: root
		    password: root
		    driverClassName: com.mysql.cj.jdbc.Driver
		    url: jdbc:mysql://127.0.0.1:3306/testmysecurity?setUnicode=true&characterEncoding=utf8&serverTimezone=UTC
```
 mysql更改引擎(InnoDB,MyISAM)的方法_Mysql_脚本之家
[ https://www.jb51.net/article/57132.htm](https://www.jb51.net/article/57132.htm) 

该连接中提到mysql默认的数据库引擎是MyISAM，不支持事务和外键，也可使用支持事务和外键的InnoDB。

实际我通过HeidiSQL尝试，mysql5.7 默认使用的是 InnoDB， 查看MySQL配置文件my.ini配置也可以看到default-storage-engine=INNODB。

Springboot2.0中Hibernate默认创建的mysql表为myisam引擎问题 - tianyaleixiaowu的专栏 - CSDN博客
[https://blog.csdn.net/tianyaleixiaowu/article/details/79468277](https://blog.csdn.net/tianyaleixiaowu/article/details/79468277)

我使用SpringBoot2中的Hibernate，配置文件application.properties文件中配置的是spring.jpa.properties.hibernate.dialect = org.hibernate.dialect.MySQL5Dialect，效果是Hibernate使用的是MyISAM（通过HeidiSQL查看）。如果通过HeidiSQL手动建表，默认是InnoDB（查看MySQL配置文件my.ini配置也可以看到default-storage-engine=INNODB）。所以这里实际有个矛盾，就是MySQL5.7默认使用的引擎是InnoDB，而SpringBoot2.0中的Hibernate默认使用的是MyISAM。结合MySQL8已经放弃了MyISAM，另外MyISAM是非事务安全的，不支持外键，我选择修改Hibernate方言配置为InnoDB。

综上，如果想要采用InnoDB，就需要MySQL和Hibernate都做InnoDB相关的配置，由于MySQL5.7默认是InnoDB，所以只需要修改application.properties文件中的方言配置如下就行：

spring.jpa.properties.hibernate.dialect = org.hibernate.dialect.MySQL5InnoDBDialect


##  8   springboot的配置文件无法读取的问题

​		配置文件的路径设置错误  
在pom.xml中可以设置配置文件的路径，配置正确即可

```xml
	<resources>
		<resource>
			<directory>src/main/resources</directory>
			<includes>
				<include>**/*.properties</include>
				<include>**/*.xml</include>
			</includes>
			<filtering>false</filtering>
		</resource>
	</resources>
```

##  9  Spring Security 基本介绍
​		这里就不对Spring Security进行过多的介绍了，具体的可以参考官方文档
我就只说下SpringSecurity核心功能:

认证（你是谁）
授权（你能干什么）
攻击防护（防止伪造身份）
基本环境搭建
这里我们以SpringBoot作为项目的基本框架，我这里使用的是maven的方式来进行的包管理，所以这里先给出集成Spring Security的方式

```xml
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
```
然后建立一个Web层请求接口

```java
@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping
    public String getUsers() {       
        return "Hello Spring Security";
    }
}
```
接下来可以直接进行项目的运行，并进行接口的调用看看效果了。

通过网页的调用
我们首先通过浏览器进行接口的调用，直接访问http://localhost:8080/user，如果接口能正常访问，那么应该显示“Hello Spring Security”。
但是我们是没法正常访问的，出现了下图的身份验证输入框
image.png
这是因为在SpringBoot中，默认的Spring Security就是生效了的，此时的接口都是被保护的，我们需要通过验证才能正常的访问。 Spring Security提供了一个默认的用户，用户名是user，而密码则是启动项目的时候自动生成的。
我们查看项目启动的日志，会发现如下的一段Log

> Using default security password: 62ccf9ca-9fbe-4993-8566-8468cc33c28c

当然你看到的password肯定和我是不一样的，我们直接用user和启动日志中的密码进行登录。

登录成功后，就跳转到了接口正常调用的页面了。
如果不想一开始就使能Spring Security，可以在配置文件中做如下的配置：

```properties
# security 使能
security.basic.enabled = false
```
刚才看到的登录框是SpringSecurity是框架自己提供的，被称为httpBasicLogin。显示它不是我们产品上想要的，我们前端一般是通过表单提交的方式进行用户登录验证的，所以我们就需要自定义自己的认证逻辑了。


####  改造1 使用页面表单登录
​		前端写一个登陆页面(使用 thymeleaf 模板引擎),login.html文件：

```xml
<!DOCTYPE html>
<html id="ng-app" ng-app="app"  xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8"/>
    <title>home</title>
</head>
<body>
<form  class="form-signin" action="/form" method="post">
    <h2 class="form-signin-heading">用户登录</h2>
    <table>
        <tr>
            <td>用户名:</td>
            <td><input type="text" name="username"  class="form-control"  placeholder="请输入用户名"/></td>
        </tr>
        <tr>
            <td>密码:</td>
            <td><input type="password" name="password"  class="form-control" placeholder="请输入密码" /></td>
        </tr>
        <tr>

            <td colspan="2">
                <button type="submit"  class="btn btn-lg btn-primary btn-block" >登录</button>
            </td>
        </tr>
    </table>
</form>
</body>
</html>
```

写一个controller方法指向该登陆页面，不能使用@RestController和@ResponseBody，否则就返回字符串了。

```java
@RequestMapping("/login")
public String userLogin() {
    return "login";
}  
```
还需要配置上：

```properties
# 定位模板的目录
spring.thymeleaf.prefix=classpath:/templates/
# 给返回的页面添加后缀名
spring.thymeleaf.suffix=.html
spring.thymeleaf.content-type=text/html
spring.thymeleaf.mode=HTML5
```
添加一个类 SecurityConfig 继承 WebSecurityConfigurerAdapter
重写configure方法,并加上@Configuration 和@EnableWebSecurity 2个注解。
	@Configuration
	@EnableWebSecurity
	public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/css/**", "/index").permitAll()       
                .antMatchers("/user/**").hasRole("USER")            
                .and()
            .formLogin()
                .and()
                .csrf().disable() //关闭CSRF
                .formLogin().loginPage("/login")
                .loginProcessingUrl("/form")
                .defaultSuccessUrl("/index") //成功登陆后跳转页面
                .failureUrl("/loginError").permitAll(); 
    }
    
}
```
与/ css / **和/ index匹配的请求是完全可访问的
与/ user / **匹配的请求要求用户进行身份验证，并且必须与USER角色相关联
使用自定义登录页面和失败URL启用基于表单的身份验证
loginPage("/login")表示登录时跳转的页面，因为登录页面我们不需要登录认证，所以我们需要添加 permitAll() 方法。

login-page 自定义登录页url,默认为/login
login-processing-url 登录请求拦截的url,也就是form表单提交时指定的action
failureUrl=表示登录出错的页面,我们可以简单写个提示：如 用户名或密码错误。

.csrf().disable() 说明：Spring Security4默认是开启CSRF的，所以需要请求中包含CSRF的token信息，这里不添加这段代码的话会出现异常，加上的话可以关闭csrf（关闭后有安全漏洞）。

> 测试：  
> 1、输入网址：http://127.0.0.1:8081/index，自动跳转到：http://127.0.0.1:8081/login，返回登陆页面  
> 2、输入账号密码：错误的话返回http://127.0.0.1:8081/loginError，登陆失败页面
> 正确的话：返回http://127.0.0.1:8081/index，登陆成功页面
> 


####  改造2、自定义用户名和密码
​			很显然，这样改造之后，虽然登录页面是好看了，但还远远不能满足我们的应用需求，所以第二步，我们改造自定义的用户名和密码。
自定义用户名和密码有2种方式，一种是在代码中写死，这也是官方的demo，另一种是使用数据库
首先是第一种：如

```java
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .inMemoryAuthentication()
                            .withUser("user").password("password").roles("USER");
    }
```
我们也照样，这是把用户名改成 admin 密码改成 123456 roles是该用户的角色，我们后面再细说。

```java
  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
              .inMemoryAuthentication()
                    .withUser("admin").password("123456").roles("USER");
        
  }
```
还有种方法 就是 重写 另外一种configure(AuthenticationManagerBuilder auth) 方法，这个和上面那个方法的作用是一样的。选其一就可。


​            
```java
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // TODO Auto-generated method stub
        auth
        .inMemoryAuthentication()
              .withUser("admin").password("123456").roles("USER")
              .and()
              .withUser("test").password("test123").roles("ADMIN");
  }
```
程序运行起来，这时用我们自己的用户名和密码 输入 admin 和123456 就可以了。

你也可以多几个用户，就多几个withUser即可。

	.and().withUser("test").password("test123").roles("ADMIN");
这样我们就有了一个用户名为test,密码为test123的用户了。

第一种的只是让我们体验了一下Spring Security而已，我们接下来就要提供自定义的用户认证机制及处理过程。
在讲这个之前，我们需要知道spring security的原理，spring security的原理就是使用很多的拦截器对URL进行拦截，以此来管理登录验证和用户权限验证。

用户登陆，会被AuthenticationProcessingFilter拦截，调用AuthenticationManager的实现，而且AuthenticationManager会调用ProviderManager来获取用户验证信息（不同的Provider调用的服务不同，因为这些信息可以是在数据库上，可以是在LDAP服务器上，可以是xml配置文件上等），如果验证通过后会将用户的权限信息封装一个User放到spring的全局缓存SecurityContextHolder中，以备后面访问资源时使用。

所以我们要自定义用户的校验机制的话，我们只要实现自己的AuthenticationProvider就可以了。在用AuthenticationProvider 这个之前，我们需要提供一个获取用户信息的服务，实现 UserDetailsService 接口

用户名密码->(Authentication(未认证) -> AuthenticationManager ->AuthenticationProvider->UserDetailService->UserDetails->Authentication(已认证）

了解了这个原理之后，我们就开始写代码

UserDetails接口
第一步：我们定义自己的用户信息类 UserInfo 继承UserDetails接口
代码如下:

```java
public class User implements UserDetails {
   private Long id;
   private String username;
   private String password;
   private String nickname;
   private boolean enabled;
   private List<Role> roles;
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
       for (Role role : roles) {
           authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
       }
       return authorities;
   }

 //....getter setter
}
```
UserDetailsService接口
然后实现第2个类 UserService 来返回这个UserInfo的对象实例

```java
@Component
public class MyUserDetailsService implements UserDetailsService {
       
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            //这里可以可以通过username（登录时输入的用户名）然后到数据库中找到对应的用户信息，并构建成我们自己的UserInfo来返回。           
            //这里可以通过数据库来查找到实际的用户信息，这里我们先模拟下,后续我们用数据库来实现
           if(username.equals("admin")) {  
              //假设返回的用户信息如下;
              User userInfo=new User();
              userInfo.setUsername("admin");
              userInfo.setPassword("123456");
              Role role = new Role(1L,"admin");
              List<Role> list = new ArrayList();
              list.add(role);
              userInfo.setRoles(list);
              return userInfo;                             
            }           
            return null;                       
      }
}
```
到这里为止，我们自己定义的UserInfo类和从数据库中返回具体的用户信息已经实现，接下来我们要实现的，我们自己的 AuthenticationProvider

AuthenticationProvider接口
新建类 MyAuthenticationProvider 继承AuthenticationProvider
完整的代码如下：

```java
@Component
public class MyAuthenticationProvider implements AuthenticationProvider {
      /**
       * 注入我们自己定义的用户信息获取对象
       */
      @Autowired
      private UserDetailsService userDetailService;
      @Override
      public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            // TODO Auto-generated method stub
            String userName = authentication.getName();// 这个获取表单输入中返回的用户名;
            String password = (String) authentication.getCredentials();// 这个是表单中输入的密码；
            // 这里构建来判断用户是否存在和密码是否正确
            UserInfo userInfo = (UserInfo) userDetailService.loadUserByUsername(userName); // 这里调用我们的自己写的获取用户的方法；
            if (userInfo == null) {
                  throw new BadCredentialsException("用户名不存在");
            }
            // //这里我们还要判断密码是否正确，实际应用中，我们的密码一般都会加密，以Md5加密为例
            // Md5PasswordEncoder md5PasswordEncoder=new Md5PasswordEncoder();
            // //这里第个参数，是salt
            // 就是加点盐的意思，这样的好处就是用户的密码如果都是123456，由于盐的不同，密码也是不一样的，就不用怕相同密码泄漏之后，不会批量被破解。
            // String encodePwd=md5PasswordEncoder.encodePassword(password, userName);
            // //这里判断密码正确与否
            // if(!userInfo.getPassword().equals(encodePwd))
            // {
            // throw new BadCredentialsException("密码不正确");
            // }
            // //这里还可以加一些其他信息的判断，比如用户账号已停用等判断，这里为了方便我接下去的判断，我就不用加密了。
            //
            //
            if (!userInfo.getPassword().equals(password )) {
                  throw new BadCredentialsException("密码不正确");
            }
            Collection<? extends GrantedAuthority> authorities = userInfo.getAuthorities();
            // 构建返回的用户登录成功的token
            return new UsernamePasswordAuthenticationToken(userInfo, password, authorities);
      }
      @Override
      public boolean supports(Class<?> authentication) {
            // TODO Auto-generated method stub
            // 这里直接改成retrun true;表示是支持这个执行
            return true;
      }
}
```
到此为止，我们的用户信息的获取，校验部分已经完成了。接下来要让它起作用，则我们需要在配置文件中修改，让他起作用。回到我的SecurityConfig代码文件，修改如下：

1、注入我们自己的AuthenticationProvider
2、修改配置的方法：

```java
@Autowired
private AuthenticationProvider provider;  //注入我们自己的AuthenticationProvider

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
```
现在重新运行程序，则需要输入用户名为 admin 密码是123456之后，才能正常登录了。
为了方便测试，我们调整添加另一个控制器 /whoim 的代码 ，让他返回当前登录的用户信息，前面说了，他是存在SecurityContextHolder 的全局变量中，所以我们可以这样获取

```java
  @RequestMapping("/whoim")
  public Object whoIm()
  {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
  }
```
我们运行，直接反问 /whoim ，则直接跳转到登录页面，我们验证过之后，再访问此url，结果如下：


####  改造3、自定义登录成功和失败的处理逻辑
​		在现在的大多数应用中，一般都是前后端分离的，所以我们登录成功或失败都需要用json格式返回，或者登录成功之后，跳转到某个具体的页面。
接下来我们来实现这种改造。

为了实现这个功能，我们需要写2个类，分别继承SavedRequestAwareAuthenticationSuccessHandler和SimpleUrlAuthenticationFailureHandler2个类，并重写其中的部分方法即可。
处理登录成功的:

```java
@Component("myAuthenticationSuccessHandler")
public class MyAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler{
  
  @Autowired
  private ObjectMapper objectMapper;
  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
              throws IOException, ServletException {            
        //什么都不做的话，那就直接调用父类的方法
        //super.onAuthenticationSuccess(request, response, authentication);        
        //这里可以根据实际情况，来确定是跳转到页面或者json格式。
        //如果是返回json格式，那么我们这么写        
        Map<String,String> map=new HashMap<>();
        map.put("code", "200");
        map.put("msg", "登录成功");
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(map));
        //如果是要跳转到某个页面的，比如我们的那个whoim的则
        //new DefaultRedirectStrategy().sendRedirect(request, response, "/whoim");
  }
}
```


​            

登录失败的:

```java
@Component("myAuthenticationFailHander")
public class MyAuthenticationFailHander extends SimpleUrlAuthenticationFailureHandler {
  @Autowired
  private ObjectMapper objectMapper;
  private Logger logger = LoggerFactory.getLogger(getClass());
  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
              AuthenticationException exception) throws IOException, ServletException {
        // TODO Auto-generated method stub
        logger.info("登录失败");
        //以Json格式返回
        Map<String,String> map=new HashMap<>();
        map.put("code", "201");
        map.put("msg", "登录失败");
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");   
        response.getWriter().write(objectMapper.writeValueAsString(map));
        
  }
}
```
代码完成之后，修改配置config类代码。
添加2个注解，自动注入

```java
@Autowired
  private AuthenticationSuccessHandler myAuthenticationSuccessHandler;
  @Autowired
  private AuthenticationFailureHandler myAuthenticationFailHander;
  
  @Override
  protected void configure(HttpSecurity http) throws Exception {
        // TODO Auto-generated method stub
        //super.configure(http);
        http
              .formLogin().loginPage("/login").loginProcessingUrl("/login/form")
              .successHandler(myAuthenticationSuccessHandler)
              .failureHandler(myAuthenticationFailHander)
              .permitAll()  //表单登录，permitAll()表示这个不需要验证 登录页面，登录失败页面
              .and()
              .authorizeRequests().anyRequest().authenticated()                  
              .and()
              .csrf().disable();            
  }
```
进行测试，成功返回json格式的（登录成功和失败的）


#### 改造4、添加权限控制
​		之前的代码我们用户的权限没有加以利用，现在我们添加权限的用法。
之前的登录验证通俗的说，就是来判断你是谁（认证），
而权限控制就是用来确定：你能做什么或者不能做什么（权限）

在讲这个之前，我们简单说下，对于一些资源不需要权限认证的，那么就可以在Config中添加 过滤条件，如：

```java
@Override
  protected void configure(HttpSecurity http) throws Exception {
        // TODO Auto-generated method stub
        //super.configure(http);
        http
              .formLogin().loginPage("/login").loginProcessingUrl("/login/form")
              .successHandler(myAuthenticationSuccessHandler)
              .failureHandler(myAuthenticationFailHander)
              .permitAll()  //表单登录，permitAll()表示这个不需要验证 登录页面，登录失败页面
              .and()
              .authorizeRequests()
                    .antMatchers("/index").permitAll()  //这就表示 /index这个页面不需要权限认证，所有人都可以访问
              .anyRequest().authenticated()             
              .and()
              .csrf().disable();            
  }
```
那么我们直接访问 /index 就不会跳转到登录页面，这样我们就可以把一些不需要验证的资源以这种方式过滤，比如图片，脚本，样式文件之类的。

我们先来看第一种权限控制：在编码中写死的。
其实权限控制也是通过这种方式来实现：

```java
   	http
          .formLogin().loginPage("/login").loginProcessingUrl("/login/form")
          .successHandler(myAuthenticationSuccessHandler)
          .failureHandler(myAuthenticationFailHander)
          .permitAll()  //表单登录，permitAll()表示这个不需要验证 登录页面，登录失败页面
          .and()
          .authorizeRequests()
                .antMatchers("/index").permitAll()                    
          .antMatchers("/whoim").hasRole("ADMIN") //这就表示/whoim的这个资源需要有ROLE_ADMIN的这个角色才能访问。不然就会提示拒绝访问
          .anyRequest().authenticated() //必须经过认证以后才能访问          
          .and()
          .csrf().disable();   
```

这个用户的角色哪里来，就是我们自己的UserDetailsService中返回的用户信息中的角色权限信息，
这里需要注意一下就是 .hasRole("ADMIN"),那么给用户的角色时就要用:ROLE_ADMIN

.antMatchers 这里也可以限定HttpMethod的不同要求不同的权限（适用于Restful风格的API).
如：Post需要 管理员权限，get 需要user权限，我们可以这么个改造，同时也可以通过通配符来是实现 如：/user/1 这种带参数的URL

```java
            .antMatchers("/whoim").hasRole("ADMIN")
            .antMatchers(HttpMethod.POST,"/user/").hasRole("ADMIN")
            .antMatchers(HttpMethod.GET,"/user/").hasRole("USER")
```

Spring Security 的校验的原理：左手配置信息，右手登录后的用户信息，中间投票器。
从我们的配置信息中获取相关的URL和需要的权限信息，然后获得登录后的用户信息，
然后经过：AccessDecisionManager 来验证，这里面有多个投票器：AccessDecisionVoter，（默认有几种实现：比如：1票否决（只要有一个不同意，就没有权限），全票通过，才算通过；只要有1个通过，就全部通过。类似这种的。
WebExpressionVoter 是Spring Security默认提供的的web开发的投票器。（表达式的投票器）

Spring Security 默认的是 AffirmativeBased 只要有一个通过，就通过。
有兴趣的可以 从FilterSecurityInterceptor这个过滤器入口，来查看这个流程。
内嵌的表达式有：permitAll denyAll 等等。
每一个权限表达式都对应一个方法。
如果需要同时满足多个要求的，不能连写如 ，我们有个URL需要管理员权限也同时要限定IP的话，不能：.hasRole("ADMIN").hasIPAddress("192.168.1.1");
而是需要用access方法 .access("hasRole('ADMIN') and hasIpAddress('192.168.1.1')");这种。

那我们可以自己写权限表达式吗？ 可以，稍后。。。这些都是硬编码的实现，都是在代码中写入的，这样的灵活性不够。所以我们接下来继续改造


####  改造5、添加基于RBAC权限控制

​		RBAC(role-Based-access control),这个大家可以去百度一下，一般都是由 3个部分组成，一个是用户，一个是角色 ，一个是资源（菜单，按钮），然后就是 用户和角色的关联表，角色和资源的关联表

核心就是判断当前的用户所拥有的URL是否和当前访问的URL是否匹配。

首先我们自己提供一个判断的接口和实现，代码如下：

```java
/**
 * 返回权限验证的接口
 */
public interface RbacService {
      boolean hasPermission(HttpServletRequest request,Authentication authentication);
}

@Component("rbacService")
public class RbacServiceImpl implements RbacService {
      private AntPathMatcher antPathMatcher = new AntPathMatcher();
      @Override
      public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
            Object principal = authentication.getPrincipal();
            boolean hasPermission = false;
            if (principal instanceof UserDetails) { //首先判断先当前用户是否是我们UserDetails对象。
                  String userName = ((UserDetails) principal).getUsername();
                  Set<String> urls = new HashSet<>(); // 数据库读取 //读取用户所拥有权限的所有URL
                  
                  urls.add("/whoim");
                  // 注意这里不能用equal来判断，因为有些URL是有参数的，所以要用AntPathMatcher来比较
                  for (String url : urls) {
                        if (antPathMatcher.match(url, request.getRequestURI())) {
                              hasPermission = true;
                              break;
                        }
                  }
            }
            return hasPermission;
      }
}
```
然后在Security的配置项中添加自定义的权限表达式就可以了。

```java
@Override
      protected void configure(HttpSecurity http) throws Exception {
            // TODO Auto-generated method stub
            //super.configure(http);
            http
                  .formLogin().loginPage("/login").loginProcessingUrl("/login/form")
                  .successHandler(myAuthenticationSuccessHandler)
                  .failureHandler(myAuthenticationFailHander)
                  .permitAll()  //表单登录，permitAll()表示这个不需要验证 登录页面，登录失败页面
                  .and()
                  .authorizeRequests()
//                      .antMatchers("/index").permitAll()                    
//                .antMatchers("/whoim").hasRole("ADMIN")
//                .antMatchers(HttpMethod.POST,"/user/*").hasRole("ADMIN")
//                .antMatchers(HttpMethod.GET,"/user/*").hasRole("USER")
                  .anyRequest().access("@rbacService.hasPermission(request,authentication)")    //必须经过认证以后才能访问            
                  .and()
                  .csrf().disable();            
      }
```
其中 @rbacService 就是我们自己声明的bean，在RbacServiceImpl实现类的头部注解中。


####  改造6   记住我功能

> 遇到的问题：不能自动注入DataSource,原因是没有在配置文件中定义数据库的配置
>
> ```properties
> #数据库驱动设置
> spring.jpa.database-platform=org.hibernate.dialect.MySQL5InnoDBDialect
> spring.jpa.show-sql= true
> spring.jpa.hibernate.ddl-auto=update
> 
> #数据库设置
> spring.datasource.username = root
> spring.datasource.password = root
> spring.datasource.driverClassName = com.mysql.cj.jdbc.Driver
> spring.datasource.url = jdbc:mysql://127.0.0.1:3306/testmysecurity?setUnicode=true&characterEncoding=utf8&serverTimezone=UTC
> ```


本质是通过token来读取用户信息，所以服务端需要存储下token信息
根据官方的文档，token可以通过数据库存储 数据库脚本

```mysql
CREATE TABLE persistent_logins (
    username VARCHAR(64) NOT NULL,
    series VARCHAR(64) NOT NULL,
    token VARCHAR(64) NOT NULL,
    last_used TIMESTAMP NOT NULL,
    PRIMARY KEY (series)
);
```
然后，配置好token 的存储 及数据源

 	  @Autowired
      private DataSource dataSource;   //是在application.properites

```java
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
```
修改Security配置

```java
  	  @Override
      protected void configure(HttpSecurity http) throws Exception {
            // TODO Auto-generated method stub
            //super.configure(http);
            http
                  .formLogin().loginPage("/login").loginProcessingUrl("/login/form")
                  .successHandler(myAuthenticationSuccessHandler)
                  .failureHandler(myAuthenticationFailHander)
                  .permitAll()  //表单登录，permitAll()表示这个不需要验证 登录页面，登录失败页面
                  .and()
                  .rememberMe()
                  .rememberMeParameter("remember-me").userDetailsService(userDetailsService)
                  .tokenRepository(persistentTokenRepository())
                  .tokenValiditySeconds(60)
                  .and()
                  .authorizeRequests()
		//        .antMatchers("/index").permitAll()                    
		//        .antMatchers("/whoim").hasRole("ADMIN")
		//        .antMatchers(HttpMethod.POST,"/user/*").hasRole("ADMIN")
		//        .antMatchers(HttpMethod.GET,"/user/*").hasRole("USER")
            .anyRequest().access("@rbacService.hasPermission(request,authentication)") //必须经过认证以后才能访问            
                  .and()
                  .csrf().disable();
		}
```


在登陆页面login.html上还要加上记住密码的勾选框

```html
<tr>
   <td colspan="2"><input type="checkbox" name="remember-me" value="true"/>记住我</td>
</tr>
```

登录之后 数据库就会有一条数据

然后，服务重新启动下，我们在看下直接访问 /index 的话，就可以直接访问了，不需要再登录了。

到此为止我们的Spring Securtiy 的基本用法已经改造完成了。



##   10   Mybatis-plus的数据库逆向工程（自动生成接口代码）

​		AutoGenerator 是 MyBatis-Plus 的代码生成器，通过 AutoGenerator 可以快速生成 Entity、Mapper、Mapper XML、Service、Controller 等各个模块的代码，极大的提升了开发效率。

```java
// 演示例子，执行 main 方法控制台输入模块表名回车自动生成对应项目目录中
public class CodeGenerator {
    /**
     * <p>
     * 读取控制台内容
     * </p>
     */
    public static String scanner(String tip) {
        Scanner scanner = new Scanner(System.in);
        StringBuilder help = new StringBuilder();
        help.append("请输入" + tip + "：");
        System.out.println(help.toString());
        if (scanner.hasNext()) {
            String ipt = scanner.next();
            if (StringUtils.isNotEmpty(ipt)) {
                return ipt;
            }
        }
        throw new MybatisPlusException("请输入正确的" + tip + "！");
    }

    public static void main(String[] args) {
        // 代码生成器
        AutoGenerator mpg = new AutoGenerator();

        // 全局配置
        GlobalConfig gc = new GlobalConfig();
        String projectPath = System.getProperty("user.dir");
        gc.setOutputDir(projectPath + "/src/main/java");
        gc.setAuthor("jobob");
        gc.setOpen(false);
        // gc.setSwagger2(true); 实体属性 Swagger2 注解
        mpg.setGlobalConfig(gc);
        // 数据源配置
        DataSourceConfig dsc = new DataSourceConfig();
        //改成自己的数据库连接
        dsc.setUrl("jdbc:mysql://localhost:3306/ant?useUnicode=true&useSSL=false&characterEncoding=utf8");
        // dsc.setSchemaName("public");
        dsc.setDriverName("com.mysql.jdbc.Driver");
        //改成自己的用户名和密码
        dsc.setUsername("root");
        dsc.setPassword("密码");
        mpg.setDataSource(dsc);

        // 包配置
        PackageConfig pc = new PackageConfig();
        pc.setModuleName(scanner("模块名"));
        //这里改成自己的路径
        pc.setParent("com.baomidou.ant");
        mpg.setPackageInfo(pc);

        // 自定义配置
        InjectionConfig cfg = new InjectionConfig() {
            @Override
            public void initMap() {
                // to do nothing
            }
        };
        // 如果模板引擎是 freemarker
        String templatePath = "/templates/mapper.xml.ftl";
        // 如果模板引擎是 velocity
        // String templatePath = "/templates/mapper.xml.vm";

        // 自定义输出配置
        List<FileOutConfig> focList = new ArrayList<>();
        // 自定义配置会被优先输出
        focList.add(new FileOutConfig(templatePath) {
            @Override
            public String outputFile(TableInfo tableInfo) {
                // 自定义输出文件名 ， 如果你 Entity 设置了前后缀、此处注意 xml 的名称会跟着发生变化！！
                return projectPath + "/src/main/resources/mapper/" + pc.getModuleName()
                        + "/" + tableInfo.getEntityName() + "Mapper" + StringPool.DOT_XML;
            }
        });
        /*
        cfg.setFileCreate(new IFileCreate() {
            @Override
            public boolean isCreate(ConfigBuilder configBuilder, FileType fileType, String filePath) {
                // 判断自定义文件夹是否需要创建
                checkDir("调用默认方法创建的目录");
                return false;
            }
        });
        */
        cfg.setFileOutConfigList(focList);
        mpg.setCfg(cfg);
        // 配置模板
        TemplateConfig templateConfig = new TemplateConfig();

        // 配置自定义输出模板
        //指定自定义模板路径，注意不要带上.ftl/.vm, 会根据使用的模板引擎自动识别
        // templateConfig.setEntity("templates/entity2.java");
        // templateConfig.setService();
        // templateConfig.setController();
        templateConfig.setXml(null);
        mpg.setTemplate(templateConfig);

        // 策略配置
        StrategyConfig strategy = new StrategyConfig();
        strategy.setNaming(NamingStrategy.underline_to_camel);
        strategy.setColumnNaming(NamingStrategy.underline_to_camel);
        //设置实体Entity的父类，目前还未用到
        strategy.setSuperEntityClass("com.baomidou.ant.common.BaseEntity");
        strategy.setEntityLombokModel(true);
        strategy.setRestControllerStyle(true);
        // Controller的公共父类，目前还没用到
        strategy.setSuperControllerClass("com.baomidou.ant.common.BaseController");
        // 写于父类中的公共字段
        strategy.setSuperEntityColumns("id");
        strategy.setInclude(scanner("表名，多个英文逗号分割").split(","));
        strategy.setControllerMappingHyphenStyle(true);
        strategy.setTablePrefix(pc.getModuleName() + "_");
        mpg.setStrategy(strategy);
        mpg.setTemplateEngine(new FreemarkerTemplateEngine());
        mpg.execute();
    }

}
```

#### 添加依赖

MyBatis-Plus 从 `3.0.3` 之后移除了代码生成器与模板引擎的默认依赖，需要手动添加相关依赖：

- 添加 代码生成器 依赖

  ```xml
  <dependency>
      <groupId>com.baomidou</groupId>
      <artifactId>mybatis-plus-generator</artifactId>
      <version>3.2.0</version>
  </dependency>
  ```

- 添加 模板引擎 依赖，MyBatis-Plus 支持 Velocity（默认）、Freemarker、Beetl，用户可以选择自己熟悉的模板引擎，如果都不满足您的要求，可以采用自定义模板引擎。

  Velocity（默认）：

  ```xml
  <dependency>
      <groupId>org.apache.velocity</groupId>
      <artifactId>velocity-engine-core</artifactId>
      <version>2.1</version>
  </dependency>
  ```

  Freemarker：

  ```xml
  <dependency>
      <groupId>org.freemarker</groupId>
      <artifactId>freemarker</artifactId>
      <version>2.3.29</version>
  </dependency>
  ```

  Beetl：

  ```xml
  <dependency>
      <groupId>com.ibeetl</groupId>
      <artifactId>beetl</artifactId>
      <version>3.0.11.RELEASE</version>
  </dependency>
  ```

  注意！如果您选择了非默认引擎，需要在 AutoGenerator 中 设置模板引擎。

#### 编写配置

MyBatis-Plus 的代码生成器提供了大量的自定义参数供用户选择，能够满足绝大部分人的使用需求。

- 配置 GlobalConfig

  ```java
  GlobalConfig globalConfig = new GlobalConfig();
  globalConfig.setOutputDir(System.getProperty("user.dir") + "/src/main/java");
  globalConfig.setAuthor("jobob");
  globalConfig.setOpen(false);
  ```

- 配置 DataSourceConfig

  ```java
  DataSourceConfig dataSourceConfig = new DataSourceConfig();
  dataSourceConfig.setUrl("jdbc:mysql://localhost:3306/ant?useUnicode=true&useSSL=false&characterEncoding=utf8");
  dataSourceConfig.setDriverName("com.mysql.jdbc.Driver");
  dataSourceConfig.setUsername("root");
  dataSourceConfig.setPassword("password");
  ```

数据库需要有对应的表，在运行main函数后，会出现，这时候输入要逆向的数据库名

> 请出入模块名：  

然后会出现 ，这时候输入要逆向的表名

> 请输入表名： 

然后就会自动生成接口代码. enjoy..



##  11 Mybatis-plus的简单使用

​		上篇讲到MP的代码生成器(AutoGenerator )的简单配置和使用，那么生成了接口代码，接下来要做的就是怎么用接口代码进行CRUD（增删改查）操作。

​		首先是配置数据库的参数：

```yaml
spring:
  application:
    name: mybatisplus
  #配置数据库
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    type: com.zaxxer.hikari.HikariDataSource
    url: jdbc:mysql://127.0.0.1:3306/testmybatisplus?useUnicode=true&characterEncoding=utf8
    username: root
    password: root
```

#### **1  C       creat a record**

```java
User user=new User();
user.setAge(12);
user.setEmail("zhang@163.com");
user.setName("zhangfengqi");
userMapper.insert(user);
```

#### **2   R      redrieve a record**

```java
User user = userMapper.selectOne(new QueryWrapper<User>().eq("name", "zhangfengqi"));
//或者
User user = iuserService.lambdaQuery().eq(User::getName, name).list().get(0);
```

**(1)、**根据id查询：

```undefined
Employee employee = emplopyeeDao.selectById(1);
```

**(2)、**根据条件查询一条数据：

```cpp
Employee employeeCondition = new Employee();
employeeCondition.setId(1);
employeeCondition.setLastName("更新测试");
//若是数据库中符合传入的条件的记录有多条，那就不能用这个方法，会报错
Employee employee = emplopyeeDao.selectOne(employeeCondition);
```

**注：**这个方法的sql语句就是`where id = 1 and last_name = 更新测试`，若是符合这个条件的记录不止一条，那么就会报错。

**(3)、**根据查询条件返回多条数据：
当符合指定条件的记录数有多条时，上面那个方法就会报错，就应该用这个方法。

```jsx
Map<String,Object> columnMap = new HashMap<>();
columnMap.put("last_name","东方不败");//写表中的列名
columnMap.put("gender","1");
List<Employee> employees = emplopyeeDao.selectByMap(columnMap);
System.out.println(employees.size());
```

**注：**查询条件用map集合封装，columnMap，写的是数据表中的列名，而非实体类的属性名。比如属性名为lastName，数据表中字段为last_name，这里应该写的是last_name。selectByMap方法返回值用list集合接收。

**(4)、**通过id批量查询：

```csharp
List<Integer> idList = new ArrayList<>();
idList.add(1);
idList.add(2);
idList.add(3);
List<Employee> employees = emplopyeeDao.selectBatchIds(idList);
System.out.println(employees);
```

**注：**把需要查询的id都add到list集合中，然后调用selectBatchIds方法，传入该list集合即可，该方法返回的是对应id的所有记录，所有返回值也是用list接收。

**(5)、**分页查询：

```csharp
List<Employee> employees = emplopyeeDao.selectPage(new Page<>(1,2),null);
System.out.println(employees);
```

**注：**selectPage方法就是分页查询，在page中传入分页信息，后者为null的分页条件，这里先让其为null，讲了条件构造器再说其用法。这个分页其实并不是物理分页，而是内存分页。也就是说，查询的时候并没有limit语句。等配置了分页插件后才可以实现真正的分页。

#### 3  U       update a record**

```java
@Test
public void testUpdate(){
        Employee employee = new Employee();
        employee.setId(1);
        employee.setLastName("更新测试");
        //emplopyeeDao.updateById(employee);//根据id进行更新，没有传值的属性就不会更新
        emplopyeeDao.updateAllColumnById(employee);//根据id进行更新，没传值的属性就更新为null
}
```

**注：**注意这两个update操作的区别，`updateById`方法，没有传值的字段不会进行更新，比如只传入了lastName，那么age、gender等属性就会保留原来的值；`updateAllColumnById`方法，顾名思义，会更新所有的列，没有传值的列会更新为null。

#### **4  D       delete a record**

**(1)、**根据id删除：

```css
emplopyeeDao.deleteById(1);
```

**(2)、**根据条件删除：

```jsx
Map<String,Object> columnMap = new HashMap<>();
columnMap.put("gender",0);
columnMap.put("age",18);
emplopyeeDao.deleteByMap(columnMap);
```

**注：**该方法与selectByMap类似，将条件封装在columnMap中，然后调用deleteByMap方法，传入columnMap即可，返回值是Integer类型，表示影响的行数。

**(3)、**根据id批量删除：

```csharp
 List<Integer> idList = new ArrayList<>();
 idList.add(1);
 idList.add(2);
 emplopyeeDao.deleteBatchIds(idList);
```

**注：**该方法和selectBatchIds类似，把需要删除的记录的id装进idList，然后调用deleteBatchIds，传入idList即可。



##  12 为项目添加Swagger测试接口

#### 1 先添加依赖

```xml
		<!--Swagger-->
        <dependency>
            <groupId>io.springfox</groupId>
            <artifactId>springfox-swagger2</artifactId>
            <version>2.2.2</version>
        </dependency>
        <dependency>
            <groupId>io.springfox</groupId>
            <artifactId>springfox-swagger-ui</artifactId>
            <version>2.2.2</version>
        </dependency>
```

#### 2 再添加swagger配置文件

```java
package com.mybatisplus.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RestController;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Parameter;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableSwagger2
public class Swagger2 {
    /*@Bean
    public Docket createRestApi() {
        ParameterBuilder tokenPar = new ParameterBuilder();
        List<Parameter> pars = new ArrayList<Parameter>();
        tokenPar.name("token").description("令牌")
                .modelRef(new ModelRef("string")).parameterType("query").required(false).build();
        pars.add(tokenPar.build());
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.sst"))
                .paths(PathSelectors.any())
                .build().globalOperationParameters(pars)  ;
    }
    @SuppressWarnings("deprecation")
    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("个人测试")
                .description("个人测试用api")
                .termsOfServiceUrl("http://blog.csdn.net/penyoudi1")
                .contact("测试")
                .version("1.0")
                .build();
    }*/
    @Bean
    public Docket createRestApi() {
        List<Parameter> pars = new ArrayList<Parameter>();
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.withClassAnnotation(RestController.class))
                .paths(PathSelectors.any())
                .build()
                .globalOperationParameters(pars)
                .apiInfo(apiInfo());
    }
    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("拾花酿春 RESTful API")
                .description("展示先做基础功能，后面再添加业务")
                .termsOfServiceUrl("https://www.cnblogs.com/xiebq/")
                .version("1.0")
                .build();
    }
}

```

#### 3 访问网址

加上 /swagger-ui.html#!

比如：http://localhost:8080/swagger-ui.html#!/

##  13   数据库插入时出错

> ERROR 2848 --- [nio-8080-exec-7] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed; nested exception is org.springframework.dao.DataIntegrityViolationException: 
>
> Error updating database.  Cause: java.sql.SQLException: Field 'id' doesn't have a default value
>
> The error may exist in com/mybatisplus/demo/testmybatisplus/mapper/UserMapper.java (best guess)
>
> The error may involve com.mybatisplus.demo.testmybatisplus.mapper.UserMapper.insert-Inline
>
> The error occurred while setting parameters
>
> SQL: INSERT INTO user  ( name, email, age )  VALUES  ( ?, ?, ? )
>
> Cause: java.sql.SQLException: Field 'id' doesn't have a default value
>
> ; Field 'id' doesn't have a default value; nested exception is java.sql.SQLException: Field 'id' doesn't have a default value] with root cause

因为数据库的id字段没有设置为自增的，所有插入的时候报错。



##   14  Swagger生成的接口不显示具体的属性值

在API中，Controller传入的参数如果是个类对象，应该在API接口显示具体的属性值，如下所示，调试了很久，发现时swagger依赖包的版本问题，引入下面的2.7.0包就不会有这个问题

```xml
  <!--Swagger-->
        <dependency>
            <groupId>io.springfox</groupId>
            <artifactId>springfox-swagger2</artifactId>
            <version>2.7.0</version>
        </dependency>
        <dependency>
            <groupId>io.springfox</groupId>
            <artifactId>springfox-swagger-ui</artifactId>
            <version>2.7.0</version>
        </dependency>
```

Response Content Type    */* 

#### Parameters

| Parameter | Value | Description | Parameter Type | Data Type |
| :-------- | :---- | :---------- | :------------- | :-------- |
| id        |       |             | query          | integer   |
| name      |       |             | query          | string    |
| age       |       |             | query          | integer   |
| email     |       |             | query          | string    |