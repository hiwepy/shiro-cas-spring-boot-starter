/**
 * <p>Coyright (R) 2014 正方软件股份有限公司。<p>
 */
package org.apache.shiro.spring.boot.cas;

import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.Filter;

import org.apache.shiro.biz.spring.ShiroFilterProxyFactoryBean;
import org.apache.shiro.spring.boot.ShiroCasProperties;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.springframework.beans.BeansException;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriUtils;


/**
 * 
 * @className ： ShiroCasPac4jFilterFactoryBean
 * @description ： TODO(描述这个类的作用)
 * @author ： <a href="https://github.com/vindell">vindell</a>
 * @date ： 2018年1月23日 下午4:04:18
 * @version V1.0
 */
public class ShiroCasPac4jFilterFactoryBean extends ShiroFilterProxyFactoryBean implements ApplicationContextAware {

	private final ShiroCasProperties properties;
	private final ServerProperties serverProperties;
	private ApplicationContext applicationContext;

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

	public ShiroCasPac4jFilterFactoryBean(ShiroCasProperties properties, ServerProperties serverProperties) {
		this.properties = properties;
		this.serverProperties = serverProperties;
	}

	@Override
	public String getLoginUrl() {
		return getCasLoginUrl(getSuccessUrl());
	}

	public String getCasLoginUrl(String successUrl) {

		StringBuilder casRedirectUrl = new StringBuilder(properties.getCasServerUrlPrefix());
		if (!casRedirectUrl.toString().endsWith("/")) {
			casRedirectUrl.append("/");
		}
		
		//loginUrl中需要加上clinetname
				/*String loginUrl = casServerUrlPrefix + "/login?service=" + shiroServerUrlPrefix + "/callback?client_name=" + clientName;
				shiroFilterFactoryBean.setLoginUrl(loginUrl);*/
				
		
		// Cas登录地址
		casRedirectUrl.append("login?service=");

		// 登出的重定向地址：用于重新回到业务系统登录界面
		StringBuilder callbackUrl = new StringBuilder(StringUtils.hasText(properties.getServerName())? properties.getServerName(): properties.getService())
				.append(StringUtils.hasText(serverProperties.getContextPath()) ? serverProperties.getContextPath() : "/")
				.append(successUrl);

		try {
			if(properties.isEncodeServiceUrl()) {
				casRedirectUrl.append(UriUtils.encodePath(callbackUrl.toString(), properties.getEncoding()));
			} else {
				casRedirectUrl.append(callbackUrl.toString());
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			casRedirectUrl.append(callbackUrl.toString());
		}

		return casRedirectUrl.toString();
	}

	// 过滤器链：实现对路径规则的拦截过滤
	@Override
	public Map<String, Filter> getFilters() {

		Map<String, Filter> filters = new LinkedHashMap<String, Filter>();

		Map<String, FilterRegistrationBean> beansOfType = getApplicationContext()
				.getBeansOfType(FilterRegistrationBean.class);
		if (!ObjectUtils.isEmpty(beansOfType)) {
			Iterator<Entry<String, FilterRegistrationBean>> ite = beansOfType.entrySet().iterator();
			while (ite.hasNext()) {
				Entry<String, FilterRegistrationBean> entry = ite.next();
				if (entry.getValue().getFilter() instanceof AccessControlFilter) {
					filters.put(entry.getKey(), entry.getValue().getFilter());
				}
			}
		}

		filters.putAll(super.getFilters());

		return filters;

	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

}
