/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
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

import org.apache.shiro.biz.authc.token.LoginProtocolAuthenticationToken;
import org.apache.shiro.biz.authc.token.LoginType;
import org.apache.shiro.biz.authc.token.LoginTypeAuthenticationToken;
import org.apache.shiro.biz.authc.token.UsernameWithoutPwdToken;

@SuppressWarnings("serial")
public class CasToken extends UsernameWithoutPwdToken implements LoginTypeAuthenticationToken, LoginProtocolAuthenticationToken {

	/** The service ticket returned by the CAS server */
    private String ticket = null;
	/** 其他参数 */
	private Map<String, Object> attrs;
	/** 登陆IP */
	private String host;
	/** 登陆协议 */
	private String protocol;

	public CasToken() {
		super();
	}

	public CasToken(String host) {
		this.host = host;
	}


	@Override
	public Object getCredentials() {
		return ticket;
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

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public Map<String, Object> getAttrs() {
		return attrs;
	}

	public void setAttrs(Map<String, Object> attrs) {
		this.attrs = attrs;
	}

	public String getTicket() {
		return ticket;
	}

	public void setTicket(String ticket) {
		this.ticket = ticket;
	}

}
