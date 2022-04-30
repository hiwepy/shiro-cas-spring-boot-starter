/*
 * Copyright (c) 2017, hiwepy (https://github.com/hiwepy).
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
package org.apache.shiro.spring.boot.cas.realm;

import java.util.Map;
import java.util.Objects;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.MapUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.ShiroCasProperties;
import org.apache.shiro.spring.boot.cas.exception.CasTicketFoundException;
import org.apache.shiro.spring.boot.cas.token.CasAssertionAuthenticationToken;
import org.apache.shiro.spring.boot.utils.CasTicketValidatorUtils;
import org.apache.shiro.util.StringUtils;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.util.AssertionHolder;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cas Stateful AuthorizingRealm
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
@Slf4j
public class CasAssertionAuthorizingRealm extends AbstractAuthorizingRealm {

	/**
	 * This class from the CAS client is used to validate a service ticket on CAS server
	 */
	private TicketValidator ticketValidator;
    private ShiroCasProperties casProperties;

    public CasAssertionAuthorizingRealm(ShiroCasProperties casProperties) {
        setAuthenticationTokenClass(CasAssertionAuthenticationToken.class);
        setCasProperties(casProperties);
    }

    @Override
    protected void onInit() {
        super.onInit();
        ensureTicketValidator();
    }

    protected TicketValidator ensureTicketValidator() {
        if (this.ticketValidator == null) {
            this.ticketValidator = CasTicketValidatorUtils.createTicketValidator(casProperties);
        }
        return this.ticketValidator;
    }


    /**
     * Authenticates a user and retrieves its information.
     *
     * @param token the authentication token
     * @throws AuthenticationException if there is an error during authentication.
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

    	CasAssertionAuthenticationToken casToken = (CasAssertionAuthenticationToken) token;

		// 如果要获取用户的更多信息，用如下方法：
		Assertion assertion = AssertionHolder.getAssertion();
		if(Objects.nonNull(assertion)) {

			casToken.setAssertion(assertion);
     		// 获取AttributePrincipal对象，这是客户端对象
     		AttributePrincipal principal = assertion.getPrincipal();
     		String username = principal.getName();
			casToken.setUsername(username);
     		// 获取更多用户属性
     		Map<String, Object> attributes = principal.getAttributes();
            String rememberMeAttributeName = casProperties.getRememberMeAttributeName();
			boolean isRemembered = MapUtils.getBoolean(attributes, rememberMeAttributeName, false);
			casToken.setRememberMe(isRemembered);

			return super.doGetAuthenticationInfo(casToken);
		}

		String ticket = (String) casToken.getCredentials();
		if (!StringUtils.hasText(ticket)) {
			throw new CasTicketFoundException("Ticket Not Found");
		}

		try {

			TicketValidator ticketValidator = ensureTicketValidator();
			// contact CAS server to validate service ticket
			Assertion casAssertion = ticketValidator.validate(ticket, casProperties.getServerName());
			casToken.setAssertion(casAssertion);
			// get principal, user id and attributes
			AttributePrincipal casPrincipal = casAssertion.getPrincipal();
			String username = casPrincipal.getName();
			casToken.setUsername(username);
			log.debug("Validate ticket : {} in CAS server : {} to retrieve user : {}", new Object[]{
				 ticket, casProperties.getCasServerUrlPrefix(), username
			});
			// 获取更多用户属性
			Map<String, Object> attributes = casPrincipal.getAttributes();
			// refresh authentication token (user id + remember me)
			String rememberMeAttributeName = casProperties.getRememberMeAttributeName();
			boolean isRemembered = MapUtils.getBoolean(attributes, rememberMeAttributeName, false);
			casToken.setRememberMe(isRemembered);

			return super.doGetAuthenticationInfo(casToken);

		} catch (Exception e) {
			throw new AuthenticationException("Unable to validate ticket [" + ticket + "]", e);
		}
    }

	public ShiroCasProperties getCasProperties() {
		return casProperties;
	}

	public void setCasProperties(ShiroCasProperties casProperties) {
		this.casProperties = casProperties;
	}

}
