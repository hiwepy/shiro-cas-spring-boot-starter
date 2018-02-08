# spring-boot-starter-shiro-cas


### 说明

 > 基于开源项目 [java-cas-client](https://github.com/apereo/java-cas-client "java-cas-client") 实现的Shiro 与 Cas 单点登录 Spring Boot Starter 实现

1. Apache Shiro是一个强大且易用的Java安全框架,执行身份验证、授权、密码学和会话管理。使用Shiro的易于理解的API,您可以快速、轻松地获得任何应用程序,从最小的移动应用程序到最大的网络和企业应用程序。
2. spring-boot-starter-shiro-cas 是在引用 [shiro-spring-boot-starter](http://mvnrepository.com/artifact/org.apache.shiro/shiro-spring-boot-starter "shiro-spring-boot-starter")、[shiro-spring-boot-web-starter](http://mvnrepository.com/artifact/org.apache.shiro/shiro-spring-boot-web-starter "shiro-spring-boot-web-starter")、[spring-boot-starter-shiro-biz](https://github.com/vindell/spring-boot-starter-shiro-biz "spring-boot-starter-shiro-biz") 的基础上整合 [java-cas-client](https://github.com/apereo/java-cas-client "java-cas-client") 的 Spring Boot 整合；
3. 整合 cas-client 实现与 Cas 认证的对接

### Maven

    <dependency>
    	<groupId>${project.groupId}</groupId>
    	<artifactId>spring-boot-starter-shiro-cas</artifactId>
    	<version>${project.version}</version>
    </dependency>

### Sample ： 

[https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-starter-shiro-cas](https://github.com/vindell/spring-boot-starter-samples/tree/master/spring-boot-starter-shiro-cas "spring-boot-starter-shiro-cas")

### 配置参考

 > application.yml

	################################################################################################################  
	###Shiro 权限控制基本配置：  
	################################################################################################################
	shiro:
	  enabled: true
	  validate-captcha: false
	  login-url: /authz/login
	  redirect-url: /authz/index
	  success-url: /index
	  unauthorized-url: /error
	  failure-url: /error
	  annotations: 
	    enabled: true
	  web: 
	    enabled: true
	  filter-chain-definition-map: 
	    / : anon
	    /*favicon.ico : anon
	    /webjars/** : anon
	    /assets/** : anon
	    /html/** : anon
	    /error* : anon
	    /logo/** : anon
	    /kaptcha* : anon
	    /sockets/** : anon
	    /logout : logout
	    /callback : cas
	    /index : sessionExpired,sessionControl,authc
	    /** : sessionExpired,sessionControl,authc
	  cas: 
	    accept-any-proxy: true
	    cas-server-login-url: http://127.0.0.1:10000/cas/login
	    cas-server-logout-url: http://127.0.0.1:10000/cas/logout
	    cas-server-url-prefix: http://127.0.0.1:10000/cas
	    enabled: true
	    encoding: UTF-8
	    server-callback-url: /callback
	    server-name: http://127.0.0.1:8080
	    ignore-pattern: /webjars/;/assets/;/authz/login;/logout;/callback
	    ignore-url-pattern-type: org.apache.shiro.spring.boot.cas.ContainsPatternsUrlPatternMatcherStrategy


### 参考资料

http://shiro.apache.org/documentation.html

http://jinnianshilongnian.iteye.com/blog/2018398

https://wiki.jasig.org/display/CASC/Home