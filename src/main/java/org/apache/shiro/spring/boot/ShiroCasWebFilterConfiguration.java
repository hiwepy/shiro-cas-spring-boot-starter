package org.apache.shiro.spring.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.biz.authc.AuthenticationFailureHandler;
import org.apache.shiro.biz.authc.AuthenticationSuccessHandler;
import org.apache.shiro.biz.realm.AuthorizingRealmListener;
import org.apache.shiro.biz.spring.ShiroFilterProxyFactoryBean;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.biz.web.filter.authc.listener.LogoutListener;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.boot.ShiroCasProperties.CaMode;
import org.apache.shiro.spring.boot.cas.CasPrincipalRepository;
import org.apache.shiro.spring.boot.cas.ShiroCasFilterFactoryBean;
import org.apache.shiro.spring.boot.cas.filter.CasAuthenticatingFilter;
import org.apache.shiro.spring.boot.cas.filter.CasLogoutFilter;
import org.apache.shiro.spring.boot.cas.realm.CasStatefulAuthorizingRealm;
import org.apache.shiro.spring.boot.utils.CasUrlUtils;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.authentication.Saml11AuthenticationFilter;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.AssertionThreadLocalFilter;
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter;
import org.jasig.cas.client.validation.AbstractTicketValidationFilter;
import org.jasig.cas.client.validation.Cas10TicketValidationFilter;
import org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter;
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter;
import org.jasig.cas.client.validation.Saml11TicketValidationFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.util.StringUtils;

/**
 * 默认拦截器
 * <p>Shiro内置了很多默认的拦截器，比如身份验证、授权等相关的。默认拦截器可以参考org.apache.shiro.web.filter.mgt.DefaultFilter中的枚举拦截器：&nbsp;&nbsp;</p>
 * <p>自定义Filter通过@Bean注解后，被Spring Boot自动注册到了容器的Filter chain中，这样导致的结果是，所有URL都会被自定义Filter过滤，而不是Shiro中配置的一部分URL。</p>
 * <p>https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#howto-disable-registration-of-a-servlet-or-filter</p>
 * <p>http://www.jianshu.com/p/bf79fdab9c19</p>
 * <p>https://www.cnblogs.com/wangyang108/p/5844447.html</p>
 */
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebFilterConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnProperty(prefix = ShiroCasProperties.PREFIX, value = "enabled", havingValue = "true")
@ConditionalOnClass({AuthenticationFilter.class})
@EnableConfigurationProperties({ ShiroCasProperties.class, ShiroBizProperties.class, ServerProperties.class })
public class ShiroCasWebFilterConfiguration extends AbstractShiroWebFilterConfiguration {
	
	@Autowired
	private ShiroCasProperties casProperties;
	@Autowired
	private ShiroBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;
	
	/*
	 * 单点登录Session监听器
	 */
	@Bean
	public ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> singleSignOutHttpSessionListener() {
		ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> registration = new ServletListenerRegistrationBean<SingleSignOutHttpSessionListener>(
				new SingleSignOutHttpSessionListener());
		registration.setOrder(1);
		return registration;
	}

	/*
	 * CAS Ticket Validation Filter </br>
	 * 该过滤器负责对Ticket的校验工作
	 */
	@Bean
	public FilterRegistrationBean<AbstractTicketValidationFilter> ticketValidationFilter() {
		FilterRegistrationBean<AbstractTicketValidationFilter> filterRegistration = new FilterRegistrationBean<AbstractTicketValidationFilter>();
		filterRegistration.setEnabled(casProperties.isEnabled()); 
		if(Protocol.CAS1.equals(casProperties.getProtocol())) {
			filterRegistration.setFilter(new Cas10TicketValidationFilter());
		}
		else if(Protocol.CAS2.equals(casProperties.getProtocol())) {
			
			filterRegistration.setFilter(new Cas20ProxyReceivingTicketValidationFilter());
			
			// Cas20ProxyReceivingTicketValidationFilter
			filterRegistration.addInitParameter(ConfigurationKeys.ACCEPT_ANY_PROXY.getName(), Boolean.toString(casProperties.isAcceptAnyProxy()));
			if(StringUtils.hasText(casProperties.getAllowedProxyChains())) {	
				filterRegistration.addInitParameter(ConfigurationKeys.ALLOWED_PROXY_CHAINS.getName(), casProperties.getAllowedProxyChains());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_OVER_POST.getName(), Boolean.toString(casProperties.isArtifactParameterOverPost()));
			if(StringUtils.hasText(casProperties.getArtifactParameterName())) {	
				filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_NAME.getName(), casProperties.getArtifactParameterName());
			}
			if(StringUtils.hasText(casProperties.getAuthenticationRedirectStrategyClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS.getName(), casProperties.getAuthenticationRedirectStrategyClass());
			}
			if(StringUtils.hasText(casProperties.getCipherAlgorithm())) {
				filterRegistration.addInitParameter(ConfigurationKeys.CIPHER_ALGORITHM.getName(), casProperties.getCipherAlgorithm());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.EAGERLY_CREATE_SESSIONS.getName(), Boolean.toString(casProperties.isEagerlyCreateSessions()));
			filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY.getName(), Boolean.toString(casProperties.isGateway()));
			if(StringUtils.hasText(casProperties.getGatewayStorageClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY_STORAGE_CLASS.getName(), casProperties.getGatewayStorageClass());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_CASE.getName(), Boolean.toString(casProperties.isIgnoreCase()));
			if(StringUtils.hasText(casProperties.getIgnorePattern())) {
				filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_PATTERN.getName(), casProperties.getIgnorePattern());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE.getName(), casProperties.getIgnoreUrlPatternType().toString());
			if(StringUtils.hasText(casProperties.getLogoutParameterName())) {
				filterRegistration.addInitParameter(ConfigurationKeys.LOGOUT_PARAMETER_NAME.getName(), casProperties.getLogoutParameterName());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.MILLIS_BETWEEN_CLEAN_UPS.getName(), Long.toString(casProperties.getMillisBetweenCleanUps()));
			if(StringUtils.hasText(casProperties.getProxyReceptorUrl())) {
				filterRegistration.addInitParameter(ConfigurationKeys.PROXY_RECEPTOR_URL.getName(), casProperties.getProxyReceptorUrl());
			}
			if(StringUtils.hasText(casProperties.getProxyCallbackUrl())) {
				filterRegistration.addInitParameter(ConfigurationKeys.PROXY_CALLBACK_URL.getName(), casProperties.getProxyCallbackUrl());
			}
			if(StringUtils.hasText(casProperties.getProxyGrantingTicketStorageClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.PROXY_GRANTING_TICKET_STORAGE_CLASS.getName(), casProperties.getProxyGrantingTicketStorageClass());
			}
			if(StringUtils.hasText(casProperties.getRelayStateParameterName())) {
				filterRegistration.addInitParameter(ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getName(), casProperties.getRelayStateParameterName());
			}
			if(StringUtils.hasText(casProperties.getRoleAttribute())) {
				filterRegistration.addInitParameter(ConfigurationKeys.ROLE_ATTRIBUTE.getName(), casProperties.getRoleAttribute());
			}
			if(StringUtils.hasText(casProperties.getSecretKey())) {
				filterRegistration.addInitParameter(ConfigurationKeys.SECRET_KEY.getName(), casProperties.getSecretKey());
			}
			if(StringUtils.hasText(casProperties.getTicketValidatorClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.TICKET_VALIDATOR_CLASS.getName(), casProperties.getTicketValidatorClass());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.TOLERANCE.getName(), Long.toString(casProperties.getTolerance()));
			
		}
		else if(Protocol.CAS3.equals(casProperties.getProtocol())) {
			filterRegistration.setFilter(new Cas30ProxyReceivingTicketValidationFilter());
		}
		else if(Protocol.SAML11.equals(casProperties.getProtocol())) {
			filterRegistration.setFilter(new Saml11TicketValidationFilter());
			// Saml11TicketValidationFilter
			filterRegistration.addInitParameter(ConfigurationKeys.TOLERANCE.getName(), Long.toString(casProperties.getTolerance()));
		}
		
		// Cas10TicketValidationFilter、Cas20ProxyReceivingTicketValidationFilter、Cas30ProxyReceivingTicketValidationFilter、Saml11TicketValidationFilter
		filterRegistration.addInitParameter(ConfigurationKeys.ENCODE_SERVICE_URL.getName(), Boolean.toString(casProperties.isEncodeServiceUrl()));
		if(StringUtils.hasText(casProperties.getEncoding())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.ENCODING.getName(), casProperties.getEncoding());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.EXCEPTION_ON_VALIDATION_FAILURE.getName(), Boolean.toString(casProperties.isExceptionOnValidationFailure()));
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_LOGIN_URL.getName(), casProperties.getCasServerLoginUrl());
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_URL_PREFIX.getName(), casProperties.getCasServerUrlPrefix());
		if(StringUtils.hasText(casProperties.getHostnameVerifier())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.HOSTNAME_VERIFIER.getName(), casProperties.getHostnameVerifier());
		}
		if(StringUtils.hasText(casProperties.getHostnameVerifierConfig())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.HOSTNAME_VERIFIER_CONFIG.getName(), casProperties.getHostnameVerifierConfig());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.REDIRECT_AFTER_VALIDATION.getName(), Boolean.toString(casProperties.isRedirectAfterValidation()));
		//filterRegistration.addInitParameter(ConfigurationKeys.RENEW.getName(), Boolean.toString(properties.isRenew()));
		if(StringUtils.hasText(casProperties.getServerName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVER_NAME.getName(), casProperties.getServerName());
		} else if(StringUtils.hasText(casProperties.getService())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVICE.getName(), casProperties.getService());
		}
		if(StringUtils.hasText(casProperties.getSslConfigFile())) {
			filterRegistration.addInitParameter(ConfigurationKeys.SSL_CONFIG_FILE.getName(), casProperties.getSslConfigFile());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.USE_SESSION.getName(), Boolean.toString(casProperties.isUseSession()));
		
		
		filterRegistration.addUrlPatterns(casProperties.getTicketValidationFilterUrlPatterns());
		filterRegistration.setOrder(3);
	    return filterRegistration;
	}
	
	/*
	 * CAS Authentication Filter </br>
	 * 该过滤器负责用户的认证工作
	 */
	@Bean
	public FilterRegistrationBean<AbstractCasFilter> authenticationFilter() {
		FilterRegistrationBean<AbstractCasFilter> filterRegistration = new FilterRegistrationBean<AbstractCasFilter>();
		if (Protocol.SAML11.equals(casProperties.getProtocol())) {
			filterRegistration.setFilter(new Saml11AuthenticationFilter());
		} else {
			filterRegistration.setFilter(new AuthenticationFilter());
		}
		
		if(StringUtils.hasText(casProperties.getAuthenticationRedirectStrategyClass())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS.getName(), casProperties.getAuthenticationRedirectStrategyClass());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_LOGIN_URL.getName(), casProperties.getCasServerLoginUrl());
		filterRegistration.addInitParameter(ConfigurationKeys.ENCODE_SERVICE_URL.getName(), Boolean.toString(casProperties.isEncodeServiceUrl()));
		filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY.getName(), Boolean.toString(casProperties.isGateway()));
		if(StringUtils.hasText(casProperties.getGatewayStorageClass())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY_STORAGE_CLASS.getName(), casProperties.getGatewayStorageClass());
		}
		if(StringUtils.hasText(casProperties.getIgnorePattern())) {
			filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_PATTERN.getName(), casProperties.getIgnorePattern());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE.getName(), casProperties.getIgnoreUrlPatternType().toString());
		//filterRegistration.addInitParameter(ConfigurationKeys.RENEW.getName(), Boolean.toString(properties.isRenew()));
		if(StringUtils.hasText(casProperties.getServerName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVER_NAME.getName(), casProperties.getServerName());
		} else if(StringUtils.hasText(casProperties.getService())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVICE.getName(), casProperties.getService());
		}
		
		filterRegistration.addUrlPatterns(casProperties.getAuthenticationFilterUrlPatterns());
		filterRegistration.setOrder(4);
		return filterRegistration;
	}

	/*
	 * CAS HttpServletRequest Wrapper Filter </br>
	 * 该过滤器对HttpServletRequest请求包装， 可通过HttpServletRequest的getRemoteUser()方法获得登录用户的登录名
	 */
	@Bean
	public FilterRegistrationBean<HttpServletRequestWrapperFilter> requestWrapperFilter() {
		FilterRegistrationBean<HttpServletRequestWrapperFilter> filterRegistration = new FilterRegistrationBean<HttpServletRequestWrapperFilter>();
		filterRegistration.setFilter(new HttpServletRequestWrapperFilter());
		filterRegistration.setEnabled(casProperties.isEnabled()); 
		filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_CASE.getName(), String.valueOf(casProperties.isIgnoreCase()));
		if(StringUtils.hasText(casProperties.getRoleAttribute())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.ROLE_ATTRIBUTE.getName(), casProperties.getRoleAttribute());
		}
		filterRegistration.addUrlPatterns(casProperties.getRequestWrapperFilterUrlPatterns());
		filterRegistration.setOrder(5);
	    return filterRegistration;
	}

	/*
	 * CAS Assertion Thread Local Filter </br>
	 * 该过滤器使得可以通过org.jasig.cas.client.util.AssertionHolder来获取用户的登录名。
	 * 比如AssertionHolder.getAssertion().getPrincipal().getName()。
	 * 这个类把Assertion信息放在ThreadLocal变量中，这样应用程序不在web层也能够获取到当前登录信息
	 */
	@Bean
	public FilterRegistrationBean<AssertionThreadLocalFilter> assertionThreadLocalFilter() {
		FilterRegistrationBean<AssertionThreadLocalFilter> filterRegistration = new FilterRegistrationBean<AssertionThreadLocalFilter>();
		filterRegistration.setFilter(new AssertionThreadLocalFilter());
		filterRegistration.setEnabled(casProperties.isEnabled());
		filterRegistration.addUrlPatterns(casProperties.getAssertionThreadLocalFilterUrlPatterns());
		filterRegistration.setOrder(6);
		return filterRegistration;
	}
	
	/*
	 * 系统登录注销过滤器；默认：org.apache.shiro.spring.boot.cas.filter.CasLogoutFilter
	 */
	@Bean("casLogout")
	@ConditionalOnMissingBean(name = "casLogout")
	public FilterRegistrationBean<CasLogoutFilter> casLogoutFilter(List<LogoutListener> logoutListeners){
		
		FilterRegistrationBean<CasLogoutFilter> registration = new FilterRegistrationBean<CasLogoutFilter>(); 
		CasLogoutFilter logoutFilter = new CasLogoutFilter();
		
		//登录注销后的重定向地址：直接进入登录页面
		if( CaMode.sso.compareTo(casProperties.getCaMode()) == 0) {
			//logoutFilter.setCasLogin(true);
			logoutFilter.setRedirectUrl(CasUrlUtils.constructLogoutRedirectUrl(casProperties, serverProperties.getServlet().getContextPath(), bizProperties.getLoginUrl()));
		} else {
			logoutFilter.setRedirectUrl(bizProperties.getLoginUrl());
		}
		registration.setFilter(logoutFilter);
		//注销监听：实现该接口可监听账号注销失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		logoutFilter.setLogoutListeners(logoutListeners);
	    
	    registration.setEnabled(false); 
	    return registration;
	}
	
	@Bean("cas")
	@ConditionalOnMissingBean(name = "cas")
	public FilterRegistrationBean<CasAuthenticatingFilter> casFilter(
			ObjectProvider<LoginListener> loginListenerProvider,
			@Autowired(required = false) List<AuthenticationSuccessHandler> successHandlers,
			@Autowired(required = false) List<AuthenticationFailureHandler> failureHandlers,
			ShiroCasProperties properties){
		FilterRegistrationBean<CasAuthenticatingFilter> registration = new FilterRegistrationBean<CasAuthenticatingFilter>(); 
		CasAuthenticatingFilter casSsoFilter = new CasAuthenticatingFilter();
		// 监听器
		casSsoFilter.setLoginListeners(loginListenerProvider.stream().collect(Collectors.toList()));
		casSsoFilter.setFailureHandlers(failureHandlers);
		casSsoFilter.setSuccessHandlers(successHandlers);
		casSsoFilter.setFailureUrl(bizProperties.getFailureUrl());
		casSsoFilter.setSuccessUrl(bizProperties.getSuccessUrl());
		registration.setFilter(casSsoFilter);
	    registration.setEnabled(false); 
	    return registration;
	}
	
	@Bean
	public Realm casRealm(@Qualifier("casRepository") CasPrincipalRepository repository,
			List<AuthorizingRealmListener> realmsListeners) {
		
		CasStatefulAuthorizingRealm casRealm = new CasStatefulAuthorizingRealm(casProperties);
		//认证账号信息提供实现：认证信息、角色信息、权限信息；业务系统需要自己实现该接口
		casRealm.setRepository(repository);
		//凭证匹配器：该对象主要做密码校验
		casRealm.setCredentialsMatcher(new AllowAllCredentialsMatcher());
		//Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		casRealm.setRealmsListeners(realmsListeners);
		//缓存相关的配置：采用提供的默认配置即可
		casRealm.setCachingEnabled(bizProperties.isCachingEnabled());
		//认证缓存配置
		casRealm.setAuthenticationCachingEnabled(bizProperties.isAuthenticationCachingEnabled());
		casRealm.setAuthenticationCacheName(bizProperties.getAuthenticationCacheName());
		//授权缓存配置
		casRealm.setAuthorizationCachingEnabled(bizProperties.isAuthorizationCachingEnabled());
		casRealm.setAuthorizationCacheName(bizProperties.getAuthorizationCacheName());
		
		return casRealm;
	}
	
	@Bean
    @Override
    protected ShiroFilterFactoryBean shiroFilterFactoryBean() {
		
		ShiroFilterProxyFactoryBean filterFactoryBean = new ShiroCasFilterFactoryBean();
		filterFactoryBean.setStaticSecurityManagerEnabled(bizProperties.isStaticSecurityManagerEnabled());
		
        //登录地址：会话不存在时访问的地址
  		filterFactoryBean.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(casProperties, serverProperties.getServlet().getContextPath(), casProperties.getServerCallbackUrl()));
  		//系统主页：登录成功后跳转路径
  		filterFactoryBean.setSuccessUrl(bizProperties.getSuccessUrl());
  		//异常页面：无权限时的跳转路径
  		filterFactoryBean.setUnauthorizedUrl(bizProperties.getUnauthorizedUrl());
      
  		//必须设置 SecurityManager
 		filterFactoryBean.setSecurityManager(securityManager);
 		//拦截规则
 		filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
 		
 		return filterFactoryBean;
        
    }

	@Bean(name = "filterShiroFilterRegistrationBean")
    protected FilterRegistrationBean<AbstractShiroFilter> filterShiroFilterRegistrationBean() throws Exception {

        FilterRegistrationBean<AbstractShiroFilter> filterRegistrationBean = new FilterRegistrationBean<AbstractShiroFilter>();
        filterRegistrationBean.setFilter((AbstractShiroFilter) shiroFilterFactoryBean().getObject());
        filterRegistrationBean.setOrder(Ordered.LOWEST_PRECEDENCE);

        return filterRegistrationBean;
    }
    
}
