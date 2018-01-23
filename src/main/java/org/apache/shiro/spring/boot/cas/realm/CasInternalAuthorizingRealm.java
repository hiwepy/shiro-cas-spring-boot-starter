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
package org.apache.shiro.spring.boot.cas.realm;

import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.realm.InternalAuthorizingRealm;
import org.apache.shiro.spring.boot.cas.token.CasToken;
import org.apache.shiro.util.StringUtils;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.util.AssertionHolder;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.Saml11TicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CasInternalAuthorizingRealm extends InternalAuthorizingRealm {

	// default name of the CAS attribute for remember me authentication (CAS 3.4.10+)
    public static final String DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";
    public static final String DEFAULT_VALIDATION_PROTOCOL = "CAS";
    
    private static Logger log = LoggerFactory.getLogger(CasInternalAuthorizingRealm.class);
    
    // this is the url of the CAS server (example : http://host:port/cas)
    private String casServerUrlPrefix;
    
    // this is the CAS service url of the application (example : http://host:port/mycontextpath/shiro-cas)
    private String casService;
    
    /* CAS protocol to use for ticket validation : CAS (default) or SAML :
       - CAS protocol can be used with CAS server version < 3.1 : in this case, no user attributes can be retrieved from the CAS ticket validation response (except if there are some customizations on CAS server side)
       - SAML protocol can be used with CAS server version >= 3.1 : in this case, user attributes can be extracted from the CAS ticket validation response
    */
    private String validationProtocol = DEFAULT_VALIDATION_PROTOCOL;
    
    // default name of the CAS attribute for remember me authentication (CAS 3.4.10+)
    private String rememberMeAttributeName = DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME;
    
    // this class from the CAS client is used to validate a service ticket on CAS server
    private TicketValidator ticketValidator;
    
    public CasInternalAuthorizingRealm() {
        setAuthenticationTokenClass(CasToken.class);
    }

    @Override
    protected void onInit() {
        super.onInit();
        ensureTicketValidator();
    }

    protected TicketValidator ensureTicketValidator() {
        if (this.ticketValidator == null) {
            this.ticketValidator = createTicketValidator();
        }
        return this.ticketValidator;
    }
    
    protected TicketValidator createTicketValidator() {
        String urlPrefix = getCasServerUrlPrefix();
        if (Protocol.SAML11.name().equalsIgnoreCase(getValidationProtocol())) {
            return new Saml11TicketValidator(urlPrefix);
        }
        return new Cas20ServiceTicketValidator(urlPrefix);
    }
    
    /**
     * Authenticates a user and retrieves its information.
     * 
     * @param token the authentication token
     * @throws AuthenticationException if there is an error during authentication.
     */
    @Override
    protected AuthenticationInfo doGetInternalAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        
    	CasToken casToken = (CasToken) token;
        if (token == null) {
            return null;
        }
        
		String ticket = (String) casToken.getCredentials();
		// 如果要获取用户的更多信息，用如下方法：
		Assertion assertion = AssertionHolder.getAssertion();
		if(assertion != null) {

     		//获取AttributePrincipal对象，这是客户端对象
     		AttributePrincipal principal = assertion.getPrincipal();
     		String username = principal.getName();
     		//获取更多用户属性
     		Map<String, Object> attributes = principal.getAttributes(); 
     		
     		casToken.setUsername(username);
     		casToken.setAttrs(attributes);
     		
            String rememberMeAttributeName = getRememberMeAttributeName();
            String rememberMeStringValue = (String)attributes.get(rememberMeAttributeName);
            boolean isRemembered = rememberMeStringValue != null && Boolean.parseBoolean(rememberMeStringValue);
            if (isRemembered) {
                casToken.setRememberMe(true);
            }
     		
		} else if (StringUtils.hasText(ticket)) {
		
			try {
				
				TicketValidator ticketValidator = ensureTicketValidator();
				// contact CAS server to validate service ticket
				Assertion casAssertion = ticketValidator.validate(ticket, getCasService());
				// get principal, user id and attributes
				AttributePrincipal casPrincipal = casAssertion.getPrincipal();
				String username = casPrincipal.getName();
				log.debug("Validate ticket : {} in CAS server : {} to retrieve user : {}", new Object[]{
				     ticket, getCasServerUrlPrefix(), username
				});

				Map<String, Object> attributes = casPrincipal.getAttributes();
				// refresh authentication token (user id + remember me)
				casToken.setUsername(username);
				casToken.setAttrs(attributes);
				String rememberMeAttributeName = getRememberMeAttributeName();
				String rememberMeStringValue = (String)attributes.get(rememberMeAttributeName);
				boolean isRemembered = rememberMeStringValue != null && Boolean.parseBoolean(rememberMeStringValue);
				if (isRemembered) {
				    casToken.setRememberMe(true);
				}
				
			} catch (Exception e) {
				throw new AuthenticationException("Unable to validate ticket [" + ticket + "]", e);
			}
		}
		
		return super.doGetInternalAuthenticationInfo(casToken);
        
    }

	@Override
	protected DelegateAuthenticationToken createDelegateAuthenticationToken(AuthenticationToken token) {
		return (DelegateAuthenticationToken) token;
	}

    public String getCasServerUrlPrefix() {
        return casServerUrlPrefix;
    }

    public void setCasServerUrlPrefix(String casServerUrlPrefix) {
        this.casServerUrlPrefix = casServerUrlPrefix;
    }

    public String getCasService() {
        return casService;
    }

    public void setCasService(String casService) {
        this.casService = casService;
    }

    public String getValidationProtocol() {
        return validationProtocol;
    }

    public void setValidationProtocol(String validationProtocol) {
        this.validationProtocol = validationProtocol;
    }

    public String getRememberMeAttributeName() {
        return rememberMeAttributeName;
    }

    public void setRememberMeAttributeName(String rememberMeAttributeName) {
        this.rememberMeAttributeName = rememberMeAttributeName;
    }
    
}
