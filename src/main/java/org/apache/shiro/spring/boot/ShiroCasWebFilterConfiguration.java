package org.apache.shiro.spring.boot;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.biz.realm.PrincipalRealmListener;
import org.apache.shiro.biz.web.filter.authc.LoginListener;
import org.apache.shiro.biz.web.filter.authc.LogoutListener;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.boot.cas.ShiroCasFilterFactoryBean;
import org.apache.shiro.spring.boot.cas.filter.CasAuthenticatingFilter;
import org.apache.shiro.spring.boot.cas.filter.ShiroCas10TicketValidationFilter;
import org.apache.shiro.spring.boot.cas.filter.ShiroCas20ProxyReceivingTicketValidationFilter;
import org.apache.shiro.spring.boot.cas.filter.ShiroCas30ProxyReceivingTicketValidationFilter;
import org.apache.shiro.spring.boot.cas.filter.ShiroSaml11TicketValidationFilter;
import org.apache.shiro.spring.boot.cas.principal.CasPrincipalRepository;
import org.apache.shiro.spring.boot.cas.realm.CasInternalAuthorizingRealm;
import org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.authentication.Saml11AuthenticationFilter;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.util.AssertionThreadLocalFilter;
import org.jasig.cas.client.util.ErrorRedirectFilter;
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;


@Configuration
@ConditionalOnWebApplication
@AutoConfigureBefore(ShiroWebAutoConfiguration.class)
@ConditionalOnClass()
@ConditionalOnProperty(prefix = ShiroCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroProperties.class, ShiroCasProperties.class })
public class ShiroCasWebFilterConfiguration extends AbstractShiroWebFilterConfiguration implements ApplicationContextAware {

	private static final Logger LOG = LoggerFactory.getLogger(ShiroCasWebFilterConfiguration.class);
	private ApplicationContext applicationContext;
	
	@Autowired
	private ShiroProperties properties;
	@Autowired
	private ShiroCasProperties casProperties;
	@Autowired
	private ServerProperties serverProperties;
	
	/**
	 * 单点登录Session监听器
	 */
	@Bean
	public ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> singleSignOutHttpSessionListener() {
		ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> registration = new ServletListenerRegistrationBean<SingleSignOutHttpSessionListener>(
				new SingleSignOutHttpSessionListener());
		registration.setOrder(1);
		return registration;
	}

	/**
	 * CAS SignOut Filter </br>
	 * 该过滤器用于实现单点登出功能，单点退出配置，一定要放在其他filter之前
	 */
	@Bean("logout")
	@ConditionalOnMissingBean(name = "logout")
	public FilterRegistrationBean singleSignOutFilter(ShiroCasProperties properties) {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setFilter(new SingleSignOutFilter());
		filterRegistration.setEnabled(properties.isEnabled());
		
		if(StringUtils.hasText(properties.getArtifactParameterName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_NAME.getName(), properties.getArtifactParameterName());
		}
		if(StringUtils.hasText(properties.getLogoutParameterName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.LOGOUT_PARAMETER_NAME.getName(), properties.getLogoutParameterName());
		}
		if(StringUtils.hasText(properties.getRelayStateParameterName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getName(), properties.getRelayStateParameterName());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_URL_PREFIX.getName(), properties.getCasServerUrlPrefix());
		filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_OVER_POST.getName(), String.valueOf(properties.isArtifactParameterOverPost()));
		filterRegistration.addInitParameter(ConfigurationKeys.EAGERLY_CREATE_SESSIONS.getName(), String.valueOf(properties.isEagerlyCreateSessions()));
		
		filterRegistration.addUrlPatterns(properties.getSignOutFilterUrlPatterns());
		filterRegistration.setOrder(3);
		return filterRegistration;
	}

	/**
	 * CAS Authentication Filter </br>
	 * 该过滤器负责用户的认证工作
	 */
	@Bean
	public FilterRegistrationBean authenticationFilter(ShiroCasProperties properties) {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		if (Protocol.SAML11.equals(properties.getProtocol())) {
			filterRegistration.setFilter(new Saml11AuthenticationFilter());
		} else {
			filterRegistration.setFilter(new AuthenticationFilter());
		}
		
		if(StringUtils.hasText(properties.getAuthenticationRedirectStrategyClass())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS.getName(), properties.getAuthenticationRedirectStrategyClass());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_LOGIN_URL.getName(), properties.getCasServerLoginUrl());
		filterRegistration.addInitParameter(ConfigurationKeys.ENCODE_SERVICE_URL.getName(), Boolean.toString(properties.isEncodeServiceUrl()));
		filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY.getName(), Boolean.toString(properties.isGateway()));
		if(StringUtils.hasText(properties.getGatewayStorageClass())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY_STORAGE_CLASS.getName(), properties.getGatewayStorageClass());
		}
		if(StringUtils.hasText(properties.getIgnorePattern())) {
			filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_PATTERN.getName(), properties.getIgnorePattern());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE.getName(), properties.getIgnoreUrlPatternType().toString());
		//filterRegistration.addInitParameter(ConfigurationKeys.RENEW.getName(), Boolean.toString(properties.isRenew()));
		if(StringUtils.hasText(properties.getServerName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVER_NAME.getName(), properties.getServerName());
		} else if(StringUtils.hasText(properties.getService())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVICE.getName(), properties.getService());
		}
		
		filterRegistration.addUrlPatterns(properties.getAuthenticationFilterUrlPatterns());
		return filterRegistration;
	}

	/**
	 * CAS Ticket Validation Filter </br>
	 * 该过滤器负责对Ticket的校验工作
	 */
	@Bean
	public FilterRegistrationBean ticketValidationFilter(ShiroCasProperties properties) {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setEnabled(properties.isEnabled()); 
		if(Protocol.CAS1.equals(properties.getProtocol())) {
			filterRegistration.setFilter(new ShiroCas10TicketValidationFilter());
		}
		else if(Protocol.CAS2.equals(properties.getProtocol())) {
			
			filterRegistration.setFilter(new ShiroCas20ProxyReceivingTicketValidationFilter());
			
			// Cas20ProxyReceivingTicketValidationFilter
			filterRegistration.addInitParameter(ConfigurationKeys.ACCEPT_ANY_PROXY.getName(), Boolean.toString(properties.isAcceptAnyProxy()));
			if(StringUtils.hasText(properties.getAllowedProxyChains())) {	
				filterRegistration.addInitParameter(ConfigurationKeys.ALLOWED_PROXY_CHAINS.getName(), properties.getAllowedProxyChains());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_OVER_POST.getName(), Boolean.toString(properties.isArtifactParameterOverPost()));
			if(StringUtils.hasText(properties.getArtifactParameterName())) {	
				filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_NAME.getName(), properties.getArtifactParameterName());
			}
			if(StringUtils.hasText(properties.getAuthenticationRedirectStrategyClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS.getName(), properties.getAuthenticationRedirectStrategyClass());
			}
			if(StringUtils.hasText(properties.getCipherAlgorithm())) {
				filterRegistration.addInitParameter(ConfigurationKeys.CIPHER_ALGORITHM.getName(), properties.getCipherAlgorithm());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.EAGERLY_CREATE_SESSIONS.getName(), Boolean.toString(properties.isEagerlyCreateSessions()));
			filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY.getName(), Boolean.toString(properties.isGateway()));
			if(StringUtils.hasText(properties.getGatewayStorageClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY_STORAGE_CLASS.getName(), properties.getGatewayStorageClass());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_CASE.getName(), Boolean.toString(properties.isIgnoreCase()));
			if(StringUtils.hasText(properties.getIgnorePattern()) && StringUtils.hasText(properties.getIgnoreUrlPatternType())) {
				filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_PATTERN.getName(), properties.getIgnorePattern());
				filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE.getName(), properties.getIgnoreUrlPatternType());
			}
			if(StringUtils.hasText(properties.getLogoutParameterName())) {
				filterRegistration.addInitParameter(ConfigurationKeys.LOGOUT_PARAMETER_NAME.getName(), properties.getLogoutParameterName());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.MILLIS_BETWEEN_CLEAN_UPS.getName(), Long.toString(properties.getMillisBetweenCleanUps()));
			if(StringUtils.hasText(properties.getProxyReceptorUrl())) {
				filterRegistration.addInitParameter(ConfigurationKeys.PROXY_RECEPTOR_URL.getName(), properties.getProxyReceptorUrl());
			}
			if(StringUtils.hasText(properties.getProxyCallbackUrl())) {
				filterRegistration.addInitParameter(ConfigurationKeys.PROXY_CALLBACK_URL.getName(), properties.getProxyCallbackUrl());
			}
			if(StringUtils.hasText(properties.getProxyGrantingTicketStorageClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.PROXY_GRANTING_TICKET_STORAGE_CLASS.getName(), properties.getProxyGrantingTicketStorageClass());
			}
			if(StringUtils.hasText(properties.getRelayStateParameterName())) {
				filterRegistration.addInitParameter(ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getName(), properties.getRelayStateParameterName());
			}
			if(StringUtils.hasText(properties.getRoleAttribute())) {
				filterRegistration.addInitParameter(ConfigurationKeys.ROLE_ATTRIBUTE.getName(), properties.getRoleAttribute());
			}
			if(StringUtils.hasText(properties.getSecretKey())) {
				filterRegistration.addInitParameter(ConfigurationKeys.SECRET_KEY.getName(), properties.getSecretKey());
			}
			if(StringUtils.hasText(properties.getTicketValidatorClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.TICKET_VALIDATOR_CLASS.getName(), properties.getTicketValidatorClass());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.TOLERANCE.getName(), Long.toString(properties.getTolerance()));
			
		}
		else if(Protocol.CAS3.equals(properties.getProtocol())) {
			filterRegistration.setFilter(new ShiroCas30ProxyReceivingTicketValidationFilter());
		}
		else if(Protocol.SAML11.equals(properties.getProtocol())) {
			filterRegistration.setFilter(new ShiroSaml11TicketValidationFilter());
			// Saml11TicketValidationFilter
			filterRegistration.addInitParameter(ConfigurationKeys.TOLERANCE.getName(), Long.toString(properties.getTolerance()));
		}
		
		// Cas10TicketValidationFilter、Cas20ProxyReceivingTicketValidationFilter、Cas30ProxyReceivingTicketValidationFilter、Saml11TicketValidationFilter
		filterRegistration.addInitParameter(ConfigurationKeys.ENCODE_SERVICE_URL.getName(), Boolean.toString(properties.isEncodeServiceUrl()));
		if(StringUtils.hasText(properties.getEncoding())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.ENCODING.getName(), properties.getEncoding());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.EXCEPTION_ON_VALIDATION_FAILURE.getName(), Boolean.toString(properties.isExceptionOnValidationFailure()));
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_LOGIN_URL.getName(), properties.getCasServerLoginUrl());
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_URL_PREFIX.getName(), properties.getCasServerUrlPrefix());
		if(StringUtils.hasText(properties.getHostnameVerifier())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.HOSTNAME_VERIFIER.getName(), properties.getHostnameVerifier());
		}
		if(StringUtils.hasText(properties.getHostnameVerifierConfig())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.HOSTNAME_VERIFIER_CONFIG.getName(), properties.getHostnameVerifierConfig());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.REDIRECT_AFTER_VALIDATION.getName(), Boolean.toString(properties.isRedirectAfterValidation()));
		//filterRegistration.addInitParameter(ConfigurationKeys.RENEW.getName(), Boolean.toString(properties.isRenew()));
		if(StringUtils.hasText(properties.getServerName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVER_NAME.getName(), properties.getServerName());
		} else if(StringUtils.hasText(properties.getService())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVICE.getName(), properties.getService());
		}
		if(StringUtils.hasText(properties.getSslConfigFile())) {
			filterRegistration.addInitParameter(ConfigurationKeys.SSL_CONFIG_FILE.getName(), properties.getSslConfigFile());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.USE_SESSION.getName(), Boolean.toString(properties.isUseSession()));
		
		
		filterRegistration.addUrlPatterns(properties.getTicketValidationFilterUrlPatterns());
	    return filterRegistration;
	}

	/**
	 * CAS HttpServletRequest Wrapper Filter </br>
	 * 该过滤器对HttpServletRequest请求包装， 可通过HttpServletRequest的getRemoteUser()方法获得登录用户的登录名
	 */
	@Bean
	public FilterRegistrationBean requestWrapperFilter(ShiroCasProperties properties) {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setFilter(new HttpServletRequestWrapperFilter());
		filterRegistration.setEnabled(properties.isEnabled()); 
		filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_CASE.getName(), String.valueOf(properties.isIgnoreCase()));
		if(StringUtils.hasText(properties.getRoleAttribute())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.ROLE_ATTRIBUTE.getName(), properties.getRoleAttribute());
		}
		filterRegistration.addUrlPatterns(properties.getRequestWrapperFilterUrlPatterns());
	    return filterRegistration;
	}

	/**
	 * CAS Assertion Thread Local Filter </br>
	 * 该过滤器使得可以通过org.jasig.cas.client.util.AssertionHolder来获取用户的登录名。
	 * 比如AssertionHolder.getAssertion().getPrincipal().getName()。
	 * 这个类把Assertion信息放在ThreadLocal变量中，这样应用程序不在web层也能够获取到当前登录信息
	 */
	@Bean
	public FilterRegistrationBean assertionThreadLocalFilter(ShiroCasProperties properties) {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setFilter(new AssertionThreadLocalFilter());
		filterRegistration.setEnabled(properties.isEnabled());
		filterRegistration.addUrlPatterns(properties.getAssertionThreadLocalFilterUrlPatterns());
		return filterRegistration;
	}
	
	/**
	 * CAS Error Redirect Filter </br>
	 */
	@Bean
	public FilterRegistrationBean errorRedirectFilter(ShiroCasProperties properties) {
		
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setFilter(new ErrorRedirectFilter());
		filterRegistration.setEnabled(properties.isErrorRedirect());
		
		filterRegistration.addInitParameter("defaultErrorRedirectPage", properties.getDefaultErrorRedirectPage());
		Map<String /* Class Name */, String /* Redirect Page Path */> errorRedirectMappings = properties.getErrorRedirectMappings();
		if(errorRedirectMappings != null) {
			Iterator<Entry<String, String>> ite = errorRedirectMappings.entrySet().iterator();
			while (ite.hasNext()) {
				Entry<String, String> entry = ite.next();
				filterRegistration.addInitParameter(entry.getKey(), entry.getValue());
			}
		}
		
		filterRegistration.addUrlPatterns(properties.getErrorRedirectFilterUrlPatterns());
		return filterRegistration;
	}
	
	@Bean("authc")
	@ConditionalOnMissingBean(name = "authc")
	public FilterRegistrationBean casFilter(ShiroCasProperties properties){
		FilterRegistrationBean registration = new FilterRegistrationBean(); 
		CasAuthenticatingFilter casSsoFilter = new CasAuthenticatingFilter();
		casSsoFilter.setFailureUrl(properties.getFailureUrl());
		registration.setFilter(casSsoFilter);
	    registration.setEnabled(false); 
	    return registration;
	}
	
	@Bean
	public Realm casRealm(@Qualifier("casRepository") CasPrincipalRepository repository,
			List<PrincipalRealmListener> realmsListeners) {
		
		CasInternalAuthorizingRealm casRealm = new CasInternalAuthorizingRealm();
		//认证账号信息提供实现：认证信息、角色信息、权限信息；业务系统需要自己实现该接口
		casRealm.setRepository(repository);
		//凭证匹配器：该对象主要做密码校验
		casRealm.setCredentialsMatcher(new AllowAllCredentialsMatcher());
		//Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		casRealm.setRealmsListeners(realmsListeners);
		//缓存相关的配置：采用提供的默认配置即可
		casRealm.setCachingEnabled(properties.isCachingEnabled());
		//认证缓存配置
		casRealm.setAuthenticationCachingEnabled(properties.isAuthenticationCachingEnabled());
		casRealm.setAuthenticationCacheName(properties.getAuthenticationCacheName());
		//授权缓存配置
		casRealm.setAuthorizationCachingEnabled(properties.isAuthorizationCachingEnabled());
		casRealm.setAuthorizationCacheName(properties.getAuthorizationCacheName());
		
		//设置cas认证地址和应用服务地址
		casRealm.setCasServerUrlPrefix(casProperties.getCasServerUrlPrefix());
		if(StringUtils.hasText(casProperties.getServerName())) {	
			casRealm.setCasService(casProperties.getServerName());
		} else {
			casRealm.setCasService(casProperties.getService());
		}
		
		return casRealm;
	}
	
	
	@Bean
    @ConditionalOnMissingBean
    @Override
    protected ShiroFilterFactoryBean shiroFilterFactoryBean() {
		
		ShiroFilterFactoryBean filterFactoryBean = new ShiroCasFilterFactoryBean(casProperties, serverProperties);
		//系统主页：登录成功后跳转路径
        filterFactoryBean.setSuccessUrl(properties.getSuccessUrl());
        //异常页面：无权限时的跳转路径
        filterFactoryBean.setUnauthorizedUrl(properties.getUnauthorizedUrl());
        
        //必须设置 SecurityManager
   		filterFactoryBean.setSecurityManager(securityManager);
   		//拦截规则
        filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
        
        return filterFactoryBean;
        
    }

    @Bean(name = "filterShiroFilterRegistrationBean")
    @ConditionalOnMissingBean
    protected FilterRegistrationBean filterShiroFilterRegistrationBean() throws Exception {

        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter((AbstractShiroFilter) shiroFilterFactoryBean().getObject());
        filterRegistrationBean.setOrder(Integer.MAX_VALUE);

        return filterRegistrationBean;
    }
    
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}
	
}
