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
package org.apache.shiro.spring.boot.cas.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.spring.boot.cas.token.CasToken;
import org.apache.shiro.spring.boot.utils.RemoteAddrUtils;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.util.AssertionHolder;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Saml11TicketValidationFilter;
import org.springframework.util.StringUtils;

public class ShiroSaml11TicketValidationFilter extends Saml11TicketValidationFilter {

	// the name of the parameter service ticket in url (i.e. ticket)
    private static final String TICKET_PARAMETER = Protocol.CAS2.getArtifactParameterName();
    
	@Override
	protected void onSuccessfulValidation(HttpServletRequest request, HttpServletResponse response,
			Assertion assertion) {
		if(!SecurityUtils.getSubject().isAuthenticated()) {
			String ticket = request.getParameter(TICKET_PARAMETER);
			CasToken token = new CasToken(RemoteAddrUtils.getRemoteAddr(request));
			if(assertion != null) {
				AssertionHolder.setAssertion(assertion);
				//获取AttributePrincipal对象，这是客户端对象
				AttributePrincipal principal = assertion.getPrincipal();
				String username = principal.getName();
				token.setUsername(username);
			}
			else if(StringUtils.hasText(ticket)) {
				token.setTicket(ticket);
			}else if(StringUtils.hasText(request.getRemoteUser())) {
				token.setUsername(request.getRemoteUser());
			}
			SecurityUtils.getSubject().login(token);
		}
	}
	
	@Override
	protected void onFailedValidation(HttpServletRequest request, HttpServletResponse response) {
		// nothing to do here.
		super.onFailedValidation(request, response);
	}
	
}
