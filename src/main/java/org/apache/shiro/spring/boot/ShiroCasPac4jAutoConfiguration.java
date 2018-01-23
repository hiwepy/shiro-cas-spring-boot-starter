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

import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.commons.collections.MapUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.boot.cas.ShiroCasFilterFactoryBean;
import org.apache.shiro.spring.boot.cas.ShiroCasPac4jFilterFactoryBean;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.jasig.cas.client.util.URIBuilder;
import org.pac4j.cas.client.CasClient;
import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.cas.config.CasProtocol;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.util.StringUtils;

import io.buji.pac4j.filter.CallbackFilter;
import io.buji.pac4j.filter.LogoutFilter;
import io.buji.pac4j.realm.Pac4jRealm;
import io.buji.pac4j.subject.Pac4jSubjectFactory;

public class ShiroCasPac4jAutoConfiguration {

	@Bean
	public Config casConfig(ShiroCasPac4jProperties casProperties, ServerProperties serverProperties) {

		// CAS
		CasConfiguration configuration = new CasConfiguration(casProperties.getCasServerLoginUrl(), casProperties.getCasProtocol() );
		configuration.setAcceptAnyProxy(casProperties.isAcceptAnyProxy());
		
		CasClient casClient = new CasClient(configuration);
		
		final URIBuilder builder;

		URL url = new URL(StringUtils.hasText(casProperties.getServerName())? casProperties.getServerName(): casProperties.getService());
		URI uri = new URI( url.getProtocol(), url.getUserInfo(), url.getHost(), url.getPort(), url.getPath(), url.getQuery(), null);
	
		
		
        if (!"https".equals(url.getProtocol()) && !"http".equals(url.getProtocol())) {
            builder = new URIBuilder(casProperties.isEncodeServiceUrl());
            builder.setScheme(request.isSecure() ? "https" : "http");
            builder.setHost(casProperties.getServerName());
        }  else {
            builder = new URIBuilder(casProperties.getServerName(), casProperties.isEncodeServiceUrl());
        }
        
        String contextPath = StringUtils.hasText(serverProperties.getContextPath()) ? serverProperties.getContextPath() : "/";
        if (contextPath.endsWith("/")) {
        	contextPath = contextPath.substring(0, contextPath.length() - 1);
		}
        
		StringBuilder callbackUrl = new StringBuilder(casProperties.getServerName())
				.append(contextPath).append("/")
				.append("callback?client_name=").append(casProperties.getClientName());
		
		casClient.setCallbackUrl(callbackUrl.toString());
		casClient.setName(casProperties.getClientName());

		final Clients clients = new Clients(casClient);

		final Config config = new Config(clients);
		return config;
	} 

    @Bean(name = "securityManager")  
   public SecurityManager securityManager() {  
       
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();  
        Pac4jRealm casRealm = pac4jRealm();  
       securityManager.setRealm(casRealm);  
       securityManager.setSubjectFactory(subjectFactory());  
       //securityManager.setCacheManager(ehCacheManager());  
       return securityManager;  
   }  

    @Bean(name = "pac4jRealm")  
    public Pac4jRealm pac4jRealm() {  
        //Pac4jRealm realm = new MyShiroRealm();  
        Pac4jRealm myShiroRealm = new MyShiroRealm();  
        return myShiroRealm;  
    }  
  
    @Bean(name = "subjectFactory")  
    public Pac4jSubjectFactory subjectFactory() {  
        Pac4jSubjectFactory subjectFactory = new Pac4jSubjectFactory();  
        return subjectFactory;  
    }  
    
    /**
     * 对shiro的过滤策略进行明确
     * @return
     */
    @Bean
    protected Map<String, Filter> filters() {
        //过滤器设置
        Map<String, Filter> filters = new HashMap<>();
        filters.put("casSecurityFilter", casSecurityFilter());
        CallbackFilter callbackFilter = new CallbackFilter();
        callbackFilter.setConfig(casConfig());
        filters.put("callbackFilter", callbackFilter);
        LogoutFilter logoutFilter = new LogoutFilter();
        logoutFilter.setConfig(casConfig());
        filters.put("logoutFilter", logoutFilter);
        
        CallbackFilter callbackFilter = new CallbackFilter();  
        callbackFilter.setConfig(config);  
        callbackFilter.setDefaultUrl("/starter");  
        shiroFilterFactoryBean.getFilters().put("casFilter", callbackFilter);  
        
        
        CallbackFilter callbackFilter = new CallbackFilter();  
        callbackFilter.setConfig(config);  
        callbackFilter.setDefaultUrl("/starter");  
        shiroFilterFactoryBean.getFilters().put("casFilter", callbackFilter);  

	//拦截器中增加callback的拦截
	
	Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
	
	filterChainDefinitionMap.put("/callback", "casFilter");
	
	shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
	
	

        return filters;
    }
    
    /**
     * 路径过滤设置
     *
     * @return
     */
    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition definition = new DefaultShiroFilterChainDefinition();
        definition.addPathDefinition("/callback", "callbackFilter");
        definition.addPathDefinition("/logout", "logoutFilter");
        definition.addPathDefinition("/**", "casSecurityFilter");
        return definition;
    }
    
    @Bean
	@ConditionalOnMissingBean
	protected ShiroFilterChainDefinition shiroFilterChainDefinition(ShiroCasProperties casProperties) {
		DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
		Map<String /* pattert */, String /* Chain names */> pathDefinitions = casProperties.getFilterChainDefinitionMap();
		if (MapUtils.isNotEmpty(pathDefinitions)) {
			chainDefinition.addPathDefinitions(pathDefinitions);
			return chainDefinition;
		}
		chainDefinition.addPathDefinition("/**", "authc");
		return chainDefinition;
	}
    
    @Bean("shiroFilter")
	@ConditionalOnMissingBean(name = "shiroFilter")
	protected ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager, 
			ShiroFilterChainDefinition shiroFilterChainDefinition, 
			ShiroCasProperties casProperties,
			ServerProperties serverProperties) {
		
		ShiroFilterFactoryBean filterFactoryBean = new ShiroCasPac4jFilterFactoryBean(casProperties, serverProperties);
		
		//系统主页：登录成功后跳转路径
        filterFactoryBean.setSuccessUrl(casProperties.getSuccessUrl());
        //异常页面：无权限时的跳转路径
        filterFactoryBean.setUnauthorizedUrl(casProperties.getUnauthorizedUrl());
        //必须设置 SecurityManager
   		filterFactoryBean.setSecurityManager(securityManager);
   		//拦截规则
        filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
        
        return filterFactoryBean;
    }
	
	@Bean("delegatingShiroFilterProxy")
	@ConditionalOnMissingBean(name = "delegatingShiroFilterProxy")
	public DelegatingFilterProxyRegistrationBean delegatingFilterProxy(AbstractShiroFilter shiroFilter){
	    //FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
		DelegatingFilterProxyRegistrationBean filterRegistrationBean = new DelegatingFilterProxyRegistrationBean("shiroFilter");
		 
		filterRegistrationBean.setOrder(Integer.MAX_VALUE);
		filterRegistrationBean.addUrlPatterns("/*");
	    return filterRegistrationBean;
	}
    
	
}
