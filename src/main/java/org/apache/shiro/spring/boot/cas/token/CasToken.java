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
package org.apache.shiro.spring.boot.cas.token;

import java.util.Map;

import org.apache.shiro.authc.HostAuthenticationToken;
import org.apache.shiro.authc.RememberMeAuthenticationToken;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.authc.token.LoginProtocolAuthenticationToken;
import org.apache.shiro.biz.authc.token.LoginType;
import org.apache.shiro.biz.authc.token.LoginTypeAuthenticationToken;

@SuppressWarnings("serial")
public class CasToken implements DelegateAuthenticationToken, HostAuthenticationToken, RememberMeAuthenticationToken,
		LoginTypeAuthenticationToken, LoginProtocolAuthenticationToken {

	/** 用户名 */
	private String username;
	/** 其他参数 */
	private Map<String, Object> attrs;
	/** 登陆IP */
	private String host;
	/** 登陆协议 */
	private String protocol;
	/** 是否记住我 */
	private boolean rememberMe = false;

	public CasToken() {
		super();
	}

	public CasToken(String username, String host, String protocol, boolean rememberMe, Map<String, Object> attrs) {
		this.username = username;
		this.host = host;
		this.protocol = protocol;
		this.rememberMe = rememberMe;
		this.attrs = attrs;
	}

	@Override
	public Object getPrincipal() {
		return username;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public String getHost() {
		return host;
	}

	@Override
	public LoginType getLoginType() {
		return LoginType.SSO;
	}

	@Override
	public String getProtocol() {
		return protocol;
	}

	@Override
	public boolean isRememberMe() {
		return rememberMe;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public void setRememberMe(boolean rememberMe) {
		this.rememberMe = rememberMe;
	}

	public Map<String, Object> getAttrs() {
		return attrs;
	}

	public void setAttrs(Map<String, Object> attrs) {
		this.attrs = attrs;
	}

}
