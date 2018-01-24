package org.apache.shiro.spring.boot.cas.filter;

import java.io.UnsupportedEncodingException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.web.filter.authc.AbstractLogoutFilter;
import org.apache.shiro.spring.boot.ShiroCasProperties;
import org.apache.shiro.util.StringUtils;
import org.springframework.web.util.UriUtils;


/**
 * 
 * @className	： CasLogoutFilter
 * @description	： 实现Shiro登录注销与Cas单点登录注销的整合
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2018年1月23日 下午1:45:21
 * @version 	V1.0
 */
public class CasLogoutFilter extends AbstractLogoutFilter {
	
	protected final ShiroCasProperties casProperties;
	
	public CasLogoutFilter(ShiroCasProperties properties) {
		this.casProperties = properties;
	}
	
	@Override
	public boolean isCasLogin() {
		return true;
	}
	
	/**
	 * 
	 * @description	：  构造单点登出请求地址
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @date 		：2018年1月23日 上午11:09:09
	 * @param request
	 * @param response
	 * @return
	 */
	@Override
	public String getCasRedirectUrl(ServletRequest request, ServletResponse response) {

		
		StringBuilder casRedirectUrl = new StringBuilder(casProperties.getCasServerUrlPrefix());
		if (!casRedirectUrl.toString().endsWith("/")) {
			casRedirectUrl.append("/");
		}
		// Cas注销地址
		casRedirectUrl.append("logout?").append(casProperties.getServiceParameterName()).append("=");
		// 登出的重定向地址：用于重新回到业务系统登录界面
		StringBuilder callbackUrl = new StringBuilder(StringUtils.hasText(casProperties.getService()) ? casProperties.getService() : casProperties.getServerName())
				.append(request.getServletContext().getContextPath()).append(getRedirectUrl());

		try {
			if(casProperties.isEncodeServiceUrl()) {
				casRedirectUrl.append(UriUtils.encodePath(callbackUrl.toString(), casProperties.getEncoding()));
			}else {
				casRedirectUrl.append(callbackUrl.toString());
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			casRedirectUrl.append(callbackUrl.toString());
		}
		
		return casRedirectUrl.toString();
	}

}
