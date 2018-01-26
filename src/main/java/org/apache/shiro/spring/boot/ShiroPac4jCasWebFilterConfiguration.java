/*
 * Copyright (c) 2010-2020, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.shiro.biz.realm.PrincipalRealmListener;
import org.apache.shiro.biz.web.filter.HttpServletSessionExpiredFilter;
import org.apache.shiro.biz.web.filter.authc.LoginListener;
import org.apache.shiro.biz.web.filter.authc.LogoutListener;
import org.apache.shiro.spring.boot.cache.ShiroEhCacheAutoConfiguration;
import org.apache.shiro.spring.boot.cas.CasPac4jUserFilter;
import org.apache.shiro.spring.boot.cas.CasRelativeUrlResolver;
import org.apache.shiro.spring.boot.cas.ShiroCasPac4jFilterFactoryBean;
import org.apache.shiro.spring.boot.utils.CasClientUtils;
import org.apache.shiro.spring.boot.utils.CasUrlUtils;
import org.apache.shiro.spring.boot.utils.StringUtils;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.util.CommonUtils;
import org.pac4j.cas.client.CasClient;
import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.cas.logout.CasLogoutHandler;
import org.pac4j.cas.logout.DefaultCasLogoutHandler;
import org.pac4j.core.authorization.authorizer.CheckHttpMethodAuthorizer;
import org.pac4j.core.client.Client;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.HttpConstants.HTTP_METHOD;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.http.AjaxRequestResolver;
import org.pac4j.core.http.DefaultAjaxRequestResolver;
import org.pac4j.core.http.HttpActionAdapter;
import org.pac4j.core.http.J2ENopHttpActionAdapter;
import org.pac4j.core.http.UrlResolver;
import org.pac4j.http.authorization.authorizer.IpRegexpAuthorizer;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.util.ObjectUtils;

import io.buji.pac4j.context.ShiroSessionStore;
import io.buji.pac4j.filter.CallbackFilter;
import io.buji.pac4j.filter.LogoutFilter;
import io.buji.pac4j.filter.SecurityFilter;


/**
 * 
 * @className	： ShiroCasPac4jWebFilterConfiguration
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2018年1月25日 下午9:06:14
 * @version 	V1.0
 * @see http://blog.csdn.net/hxpjava1/article/details/77934056
 */
@Configuration
@AutoConfigureAfter({ ShiroEhCacheAutoConfiguration.class })
@AutoConfigureBefore(value = { ShiroCasWebFilterConfiguration.class}, name = {"org.apache.shiro.spring.boot.ShiroBizWebFilterConfiguration"})
@ConditionalOnClass({CallbackFilter.class, SecurityFilter.class, LogoutFilter.class, CasConfiguration.class})
@ConditionalOnProperty(prefix = ShiroPac4jCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroPac4jCasProperties.class, ShiroCasProperties.class, ShiroProperties.class, ServerProperties.class })
public class ShiroPac4jCasWebFilterConfiguration extends AbstractShiroWebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private ShiroPac4jCasProperties pac4jProperties;
	@Autowired
	private ShiroCasProperties casProperties;
	@Autowired
	private ShiroProperties properties;
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
	
	@Bean
	@ConditionalOnMissingBean
    public CasLogoutHandler<WebContext> logoutHandler(){
		return new DefaultCasLogoutHandler<WebContext>();
	}
	
	@Bean
	@ConditionalOnMissingBean
	protected UrlResolver urlResolver() {
		return new CasRelativeUrlResolver(serverProperties.getContextPath());
	}
	
	@Bean
    public CasConfiguration casConfiguration(CasLogoutHandler<WebContext> logoutHandler, UrlResolver urlResolver) {

		// 完整的cas登录地址,比如client项目的https://passport.xxx.com/login?service=https://client.xxx.com
		String serverLoginUrl = CasUrlUtils.constructLoginRedirectUrl(casProperties, serverProperties.getContextPath(), casProperties.getServerCallbackUrl());
		
		CasConfiguration configuration = new CasConfiguration(serverLoginUrl, pac4jProperties.getCasProtocol() );
		
		if(casProperties.isAcceptAnyProxy() && StringUtils.hasText(casProperties.getAllowedProxyChains())) {	
			configuration.setAcceptAnyProxy(casProperties.isAcceptAnyProxy());
			configuration.setAllowedProxyChains(CommonUtils.createProxyList(casProperties.getAllowedProxyChains()));
		}
		
		if(StringUtils.hasText(casProperties.getEncoding())) {	
			configuration.setEncoding(casProperties.getEncoding());
		}
		configuration.setGateway(casProperties.isGateway());
		configuration.setLoginUrl(casProperties.getCasServerLoginUrl());
		configuration.setLogoutHandler(logoutHandler);
		if(StringUtils.hasText(casProperties.getServiceParameterName())) {	
			configuration.setPostLogoutUrlParameter(casProperties.getServiceParameterName());
		}
		configuration.setPrefixUrl(casProperties.getCasServerUrlPrefix());
		configuration.setProtocol(pac4jProperties.getCasProtocol());
		//configuration.setRenew(casProperties.isRenew());
		configuration.setRestUrl(casProperties.getCasServerRestUrl());
		configuration.setTimeTolerance(casProperties.getTolerance());
		configuration.setUrlResolver(urlResolver);
		
		return configuration;
	}

	@Bean
	@ConditionalOnMissingBean
	protected AjaxRequestResolver ajaxRequestResolver() {
		return new DefaultAjaxRequestResolver();
	}
	
	@Bean
	@ConditionalOnMissingBean
	protected SessionStore<J2EContext> sessionStore() {
		return new ShiroSessionStore();
	}
	
	@Bean
	@ConditionalOnMissingBean
	protected HttpActionAdapter<Object, J2EContext> httpActionAdapter() {
		return J2ENopHttpActionAdapter.INSTANCE;
	}
	
	@SuppressWarnings("rawtypes")
	@Bean
	public Config casConfig(CasConfiguration configuration, AjaxRequestResolver ajaxRequestResolver, UrlResolver urlResolver,
			HttpActionAdapter<Object, J2EContext> httpActionAdapter,SessionStore<J2EContext> sessionStore) {

		final Clients clients = new Clients();
		final List<Client> clientList = new ArrayList<Client>();
		CasClient casClient = CasClientUtils.casClient(configuration, pac4jProperties, serverProperties);
		clientList.add(casClient);
		if(pac4jProperties.isDirectCasClient()) {
			clientList.add(CasClientUtils.directCasClient(configuration, pac4jProperties));
		}
		if(pac4jProperties.isDirectCasProxyClient()) {
			clientList.add(CasClientUtils.directCasProxyClient(configuration, pac4jProperties, casProperties.getCasServerUrlPrefix()));
		}
		if(pac4jProperties.isCasRestBasicAuthClient()) {
			clientList.add(CasClientUtils.casRestBasicAuthClient(configuration, pac4jProperties));
		}
		if(pac4jProperties.isCasRestFormClient()) {
			clientList.add(CasClientUtils.casRestFormClient(configuration, pac4jProperties));
		}
		
		clients.setAjaxRequestResolver(ajaxRequestResolver);
		clients.setCallbackUrl(pac4jProperties.getCallbackUrl());
		clients.setClients(clientList);
		clients.setClientNameParameter(pac4jProperties.getClientParameterName());
		clients.setDefaultClient(casClient);
		clients.setUrlResolver(urlResolver);
		
		final Config config = new Config(clients);
		
		if(StringUtils.hasText(pac4jProperties.getAllowedIpRegexpPattern())) {	
			config.addAuthorizer("isIPAuthenticated", new IpRegexpAuthorizer(pac4jProperties.getAllowedIpRegexpPattern()));
		}
		if(ArrayUtils.isNotEmpty(pac4jProperties.getAllowedHttpMethods())) {	
			String[] allowedHttpMethods = pac4jProperties.getAllowedHttpMethods();
			List<HTTP_METHOD> methods = new ArrayList<HTTP_METHOD>();
			for (String method : allowedHttpMethods) {
				methods.add(HTTP_METHOD.valueOf(method));
			}
			config.addAuthorizer("isMethodAuthenticated", new CheckHttpMethodAuthorizer(methods));
		}
		
		/*excludePath
		excludeRegex
		excludeBranch
		
		[] methods
		private String headerName;
	    private String expectedValue;*/
	    
	    
		//config.addMatcher("path", new AntPathMatcher().excludePath("").excludeBranch("").excludeRegex(""));
		//config.addMatcher("header", new HeaderMatcher());
		//config.addMatcher("method", new HttpMethodMatcher());
		
		config.setClients(clients);
		config.setHttpActionAdapter(httpActionAdapter);
		config.setSessionStore(sessionStore);
		
		return config;
	}
	/**
	 * 登录监听：实现该接口可监听账号登录失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 */
	@Bean("loginListeners")
	@ConditionalOnMissingBean(name = "loginListeners")
	public List<LoginListener> loginListeners() {

		List<LoginListener> loginListeners = new ArrayList<LoginListener>();
		
		Map<String, LoginListener> beansOfType = getApplicationContext().getBeansOfType(LoginListener.class);
		if (!ObjectUtils.isEmpty(beansOfType)) {
			Iterator<Entry<String, LoginListener>> ite = beansOfType.entrySet().iterator();
			while (ite.hasNext()) {
				loginListeners.add(ite.next().getValue());
			}
		}
		
		return loginListeners;
	}
	
	/**
	 * Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 */
	@Bean("realmListeners")
	@ConditionalOnMissingBean(name = "realmListeners")
	public List<PrincipalRealmListener> realmListeners() {

		List<PrincipalRealmListener> realmListeners = new ArrayList<PrincipalRealmListener>();
		
		Map<String, PrincipalRealmListener> beansOfType = getApplicationContext().getBeansOfType(PrincipalRealmListener.class);
		if (!ObjectUtils.isEmpty(beansOfType)) {
			Iterator<Entry<String, PrincipalRealmListener>> ite = beansOfType.entrySet().iterator();
			while (ite.hasNext()) {
				realmListeners.add(ite.next().getValue());
			}
		}
		
		return realmListeners;
	}
	
	/**
	 * 注销监听：实现该接口可监听账号注销失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 */
	@Bean("logoutListeners")
	@ConditionalOnMissingBean(name = "logoutListeners")
	public List<LogoutListener> logoutListeners() {

		List<LogoutListener> logoutListeners = new ArrayList<LogoutListener>();
		
		Map<String, LogoutListener> beansOfType = getApplicationContext().getBeansOfType(LogoutListener.class);
		if (!ObjectUtils.isEmpty(beansOfType)) {
			Iterator<Entry<String, LogoutListener>> ite = beansOfType.entrySet().iterator();
			while (ite.hasNext()) {
				logoutListeners.add(ite.next().getValue());
			}
		}
		
		return logoutListeners;
	}
	
	/**
	 * 默认的Session过期过滤器 ：解决Ajax请求期间会话过期异常处理
	 */
	@Bean("sessionExpired")
	@ConditionalOnMissingBean(name = "sessionExpired")
	public FilterRegistrationBean sessionExpiredFilter(){
		FilterRegistrationBean registration = new FilterRegistrationBean(new HttpServletSessionExpiredFilter()); 
	    registration.setEnabled(false); 
	    return registration;
	}
	
	/**
	 * 账号注销过滤器 ：处理账号注销
	 */
	@Bean("logout")
	@ConditionalOnMissingBean(name = "logout")
	public FilterRegistrationBean logoutFilter(Config config){
		
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		
		LogoutFilter logoutFilter = new LogoutFilter();
	    
		// Whether the centralLogout must be performed（是否注销统一身份认证）
        logoutFilter.setCentralLogout(pac4jProperties.isCentralLogout());
		// Security Configuration
        logoutFilter.setConfig(config);
        
        // Default logourl url
        logoutFilter.setDefaultUrl( CasUrlUtils.constructLogoutRedirectUrl(casProperties, serverProperties.getContextPath(), properties.getLoginUrl()) );
        // Whether the application logout must be performed（是否注销本地应用身份认证）
        logoutFilter.setLocalLogout(pac4jProperties.isLocalLogout());
        // Pattern that logout urls must match（注销登录路径规则，用于匹配登录请求操作）
        logoutFilter.setLogoutUrlPattern(pac4jProperties.getLogoutUrlPattern());
        
        filterRegistration.setFilter(logoutFilter);
	    filterRegistration.setEnabled(false); 
	    
	    return filterRegistration;
	}
	
	/**
	 * 权限控制过滤器 ：实现权限认证
	 */
	@Bean("authc")
	@ConditionalOnMissingBean(name = "authc")
	public FilterRegistrationBean casSecurityFilter(Config config){
		
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		
		SecurityFilter securityFilter = new SecurityFilter();  
		
		// List of authorizers
		securityFilter.setAuthorizers(pac4jProperties.getAuthorizers());
		// List of clients for authentication
		securityFilter.setClients(pac4jProperties.getClients());
		// Security configuration
		securityFilter.setConfig(config);
		securityFilter.setMatchers(pac4jProperties.getMatchers());
		// Whether multiple profiles should be kept
		securityFilter.setMultiProfile(pac4jProperties.isMultiProfile());
		
        filterRegistration.setFilter(securityFilter);
	    filterRegistration.setEnabled(false); 
	    
	    return filterRegistration;
	}
	
	
	@Bean("user")
	@ConditionalOnMissingBean(name = "user")
	public FilterRegistrationBean casSsoFilter(){
		FilterRegistrationBean registration = new FilterRegistrationBean(); 
		CasPac4jUserFilter userFilter = new CasPac4jUserFilter();
		userFilter.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(casProperties, serverProperties.getContextPath(), casProperties.getServerCallbackUrl()));
		registration.setFilter(userFilter);
	    registration.setEnabled(false); 
	    return registration;
	}
	
	
	/**
	 * 回调过滤器 ：处理登录后的回调访问
	 */
	@Bean("cas")
	@ConditionalOnMissingBean(name = "cas")
	public FilterRegistrationBean callbackFilter(Config config){
		
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		
	    CallbackFilter callbackFilter = new CallbackFilter();
	    
	    // Security Configuration
        callbackFilter.setConfig(config);
        // Default url after login if none was requested（登录成功后的重定向地址，等同于shiro的successUrl）
        callbackFilter.setDefaultUrl(CasUrlUtils.constructCallbackUrl( serverProperties.getContextPath(), properties.getSuccessUrl()));
        // Whether multiple profiles should be kept
        callbackFilter.setMultiProfile(pac4jProperties.isMultiProfile());
        
        filterRegistration.setFilter(callbackFilter);
	    filterRegistration.setEnabled(false); 
	    
	    return filterRegistration;
	}
	
	/**
	 * 权限控制过滤器 ：权限过滤链的入口（仅是FactoryBean需要引用）
	 */
	@Bean
    @ConditionalOnMissingBean
    @Override
	protected ShiroFilterFactoryBean shiroFilterFactoryBean() {

		ShiroFilterFactoryBean filterFactoryBean = new ShiroCasPac4jFilterFactoryBean();
		
		// 登录地址：会话不存在时访问的地址
		filterFactoryBean.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(casProperties, serverProperties.getContextPath(), CasUrlUtils.constructCallbackUrl(pac4jProperties)));
		// 系统主页：登录成功后跳转路径
		filterFactoryBean.setSuccessUrl(properties.getSuccessUrl());
		// 异常页面：无权限时的跳转路径
		filterFactoryBean.setUnauthorizedUrl(properties.getUnauthorizedUrl());
		
		// 必须设置 SecurityManager
		filterFactoryBean.setSecurityManager(securityManager);
		// 拦截规则
		filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
		
		return filterFactoryBean;
	}
	
	/**
	 * 权限控制过滤器 ：权限过滤链的入口
	 */
    @Bean(name = "filterShiroFilterRegistrationBean")
    @ConditionalOnMissingBean
    protected FilterRegistrationBean filterShiroFilterRegistrationBean() throws Exception {

        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter((AbstractShiroFilter) shiroFilterFactoryBean().getObject());
        filterRegistrationBean.setOrder(Ordered.LOWEST_PRECEDENCE);

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
