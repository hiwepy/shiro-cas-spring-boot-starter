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
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.shiro.spring.boot.cas.AntPathMatcher;
import org.apache.shiro.spring.boot.cas.ShiroCasPac4jFilterFactoryBean;
import org.apache.shiro.spring.boot.utils.CasClientUtils;
import org.apache.shiro.spring.boot.utils.StringUtils;
import org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.jasig.cas.client.validation.ProxyList;
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
import org.pac4j.core.http.DefaultUrlResolver;
import org.pac4j.core.http.HttpActionAdapter;
import org.pac4j.core.http.J2ENopHttpActionAdapter;
import org.pac4j.core.http.UrlResolver;
import org.pac4j.core.matching.HeaderMatcher;
import org.pac4j.core.matching.HttpMethodMatcher;
import org.pac4j.http.authorization.authorizer.IpRegexpAuthorizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.buji.pac4j.context.ShiroSessionStore;
import io.buji.pac4j.filter.CallbackFilter;
import io.buji.pac4j.filter.LogoutFilter;
import io.buji.pac4j.filter.SecurityFilter;

@Configuration
@ConditionalOnWebApplication
@AutoConfigureBefore(ShiroWebAutoConfiguration.class)
@ConditionalOnClass(CasConfiguration.class)
@ConditionalOnProperty(prefix = ShiroCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroProperties.class, ShiroCasPac4jProperties.class })
public class ShiroCasPac4jWebFilterConfiguration extends AbstractShiroWebFilterConfiguration {
	
	@Autowired
	private ShiroProperties properties;
	@Autowired
	private ShiroCasPac4jProperties casProperties;
	@Autowired
	private ServerProperties serverProperties;
	
	@Bean
	@ConditionalOnMissingBean
    public CasLogoutHandler<WebContext> logoutHandler(){
		return new DefaultCasLogoutHandler<WebContext>();
	}
	
	@Bean
	@ConditionalOnMissingBean
	protected UrlResolver urlResolver() {
		return new DefaultUrlResolver();
	}
	
	@Bean
    public CasConfiguration casConfiguration(CasLogoutHandler<WebContext> logoutHandler, UrlResolver urlResolver) {

		CasConfiguration configuration = new CasConfiguration(casProperties.getCasServerLoginUrl(), casProperties.getCasProtocol() );
		
		if(casProperties.isAcceptAnyProxy() && StringUtils.hasText(casProperties.getAllowedProxyChains())) {	
			List<String[]> proxyChains = new ArrayList<String[]>();
			proxyChains.add(StringUtils.tokenizeToStringArray(casProperties.getAllowedProxyChains()));
			configuration.setAcceptAnyProxy(casProperties.isAcceptAnyProxy());
			configuration.setAllowedProxyChains(new ProxyList(proxyChains));
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
		configuration.setProtocol(casProperties.getCasProtocol());
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
		CasClient casClient = CasClientUtils.casClient(configuration, casProperties, serverProperties);
		clientList.add(casClient);
		if(casProperties.isDirectCasClient()) {
			clientList.add(CasClientUtils.directCasClient(configuration, casProperties));
		}
		if(casProperties.isDirectCasProxyClient()) {
			clientList.add(CasClientUtils.directCasProxyClient(configuration, casProperties));
		}
		if(casProperties.isCasRestBasicAuthClient()) {
			clientList.add(CasClientUtils.casRestBasicAuthClient(configuration, casProperties));
		}
		if(casProperties.isCasRestFormClient()) {
			clientList.add(CasClientUtils.casRestFormClient(configuration, casProperties));
		}
		
		clients.setAjaxRequestResolver(ajaxRequestResolver);
		clients.setCallbackUrl(casProperties.getCallbackUrl());
		clients.setClients(clientList);
		clients.setClientNameParameter(casProperties.getClientParameterName());
		clients.setDefaultClient(casClient);
		clients.setUrlResolver(urlResolver);
		
		final Config config = new Config(clients);
		
		if(StringUtils.hasText(casProperties.getAllowedIpRegexpPattern())) {	
			config.addAuthorizer("isIPAuthenticated", new IpRegexpAuthorizer(casProperties.getAllowedIpRegexpPattern()));
		}
		if(ArrayUtils.isNotEmpty(casProperties.getAllowedHttpMethods())) {	
			String[] allowedHttpMethods = casProperties.getAllowedHttpMethods();
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
	    
	    
		config.addMatcher("path", new AntPathMatcher().excludePath("").excludeBranch("").excludeRegex(""));
		config.addMatcher("header", new HeaderMatcher());
		config.addMatcher("method", new HttpMethodMatcher());
		
		config.setClients(clients);
		config.setHttpActionAdapter(httpActionAdapter);
		config.setSessionStore(sessionStore);
		
		return config;
	}

	/**
	 * 回调过滤器 ：处理登录后的回调访问
	 */
	@Bean("callback")
	@ConditionalOnMissingBean(name = "callback")
	public FilterRegistrationBean callbackFilter(Config config){
		
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		
	    CallbackFilter callbackFilter = new CallbackFilter();
	    
	    // Security Configuration
        callbackFilter.setConfig(config);
        // Default url after login if none was requested（登录成功后的重定向地址，等同于shiro的successUrl）
        callbackFilter.setDefaultUrl(properties.getSuccessUrl());
        // Whether multiple profiles should be kept
        callbackFilter.setMultiProfile(casProperties.isMultiProfile());
        
        filterRegistration.setFilter(callbackFilter);
	    filterRegistration.setEnabled(false); 
	    
	    return filterRegistration;
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
        logoutFilter.setCentralLogout(casProperties.isCentralLogout());
		// Security Configuration
        logoutFilter.setConfig(config);
        // Default logourl url
        logoutFilter.setDefaultUrl( casProperties.isEnabled() ? casProperties.getCasServerLoginUrl() : properties.getLoginUrl());
        // Whether the application logout must be performed（是否注销本地应用身份认证）
        logoutFilter.setLocalLogout(casProperties.isLocalLogout());
        // Pattern that logout urls must match（注销登录路径规则，用于匹配登录请求操作）
        logoutFilter.setLogoutUrlPattern(casProperties.getLogoutUrlPattern());
        
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
		securityFilter.setAuthorizers(casProperties.getAuthorizers());
		// List of clients for authentication
		securityFilter.setClients(casProperties.getClients());
		// Security configuration
		securityFilter.setConfig(config);
		securityFilter.setMatchers(casProperties.getMatchers());
		// Whether multiple profiles should be kept
		securityFilter.setMultiProfile(casProperties.isMultiProfile());
		
        filterRegistration.setFilter(securityFilter);
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

		ShiroFilterFactoryBean filterFactoryBean = new ShiroCasPac4jFilterFactoryBean(casProperties, serverProperties);

		// 登录地址：此处由FactoryBean构建
		//filterFactoryBean.setLoginUrl(loginUrl);
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
        filterRegistrationBean.setOrder(Integer.MAX_VALUE);

        return filterRegistrationBean;
    }
    
}
