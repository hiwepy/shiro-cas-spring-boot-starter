package org.apache.shiro.spring.boot.cas.filter;

import java.io.UnsupportedEncodingException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.web.filter.authc.AbstractLogoutFilter;
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
	
	/** Cas注销地址 */ 
	protected final String casServerLogoutUrl;
	/** 业务系统地址 */
	protected final String serviceUrl;
	
	public CasLogoutFilter(String casServerLogoutUrl, String serviceUrl) {
		this.casServerLogoutUrl = casServerLogoutUrl;
		this.serviceUrl = serviceUrl;
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

		StringBuilder casRedirectUrl = new StringBuilder(getCasServerLogoutUrl()).append("?service=");
		// 登出的重定向地址：用于重新回到业务系统登录界面
		StringBuilder callbackUrl = new StringBuilder(getServiceUrl())
				.append(request.getServletContext().getContextPath()).append(getRedirectUrl());

		try {
			casRedirectUrl.append(UriUtils.encodePath(callbackUrl.toString(), "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			casRedirectUrl.append(callbackUrl.toString());
		}
		
		return casRedirectUrl.toString();
	}

	public String getCasServerLogoutUrl() {
		return casServerLogoutUrl;
	}

	public String getServiceUrl() {
		return serviceUrl;
	}
	
}
