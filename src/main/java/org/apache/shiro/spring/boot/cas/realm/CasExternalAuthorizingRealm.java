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
package org.apache.shiro.spring.boot.cas.realm;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.ShiroCasProperties;
import org.apache.shiro.spring.boot.cas.exception.CasAuthenticationException;
import org.apache.shiro.spring.boot.cas.token.CasToken;
import org.apache.shiro.spring.boot.utils.CasTicketValidatorUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.util.AssertionHolder;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CasExternalAuthorizingRealm extends AbstractAuthorizingRealm<String> {

    private static Logger log = LoggerFactory.getLogger(CasExternalAuthorizingRealm.class);

    // this class from the CAS client is used to validate a service ticket on CAS server
    private TicketValidator ticketValidator;
    private ShiroCasProperties casProperties;
    
    // default roles to applied to authenticated user
    private String defaultRoles;
    
    // default permissions to applied to authenticated user
    private String defaultPermissions;
    
    // names of attributes containing roles
    private String roleAttributeNames;
    
    // names of attributes containing permissions
    private String permissionAttributeNames;
    
    public CasExternalAuthorizingRealm(ShiroCasProperties casProperties) {
        setAuthenticationTokenClass(CasToken.class);
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
        
    	CasToken casToken = (CasToken) token;
        if (token == null) {
            return null;
        }
        
        // 如果要获取用户的更多信息，用如下方法：
		Assertion assertion = AssertionHolder.getAssertion();
		if(assertion != null) {

     		//获取AttributePrincipal对象，这是客户端对象
     		AttributePrincipal principal = assertion.getPrincipal();
     		String username = principal.getName();
     		//获取更多用户属性
     		Map<String, Object> attributes = principal.getAttributes(); 
     		
     		casToken.setUsername(username);
            String rememberMeAttributeName = casProperties.getRememberMeAttributeName();
            String rememberMeStringValue = (String)attributes.get(rememberMeAttributeName);
            boolean isRemembered = rememberMeStringValue != null && Boolean.parseBoolean(rememberMeStringValue);
            if (isRemembered) {
                casToken.setRememberMe(true);
            }
            // create simple authentication info
            List<Object> principals = CollectionUtils.asList(username, attributes);
            PrincipalCollection principalCollection = new SimplePrincipalCollection(principals, getName());
            return new SimpleAuthenticationInfo(principalCollection, null);
     		
		}
		
        String ticket = (String) casToken.getCredentials();
        if (!StringUtils.hasText(ticket)) {
            return null;
        }
        
        TicketValidator ticketValidator = ensureTicketValidator();

        try {
        	
            // contact CAS server to validate service ticket
            Assertion casAssertion = ticketValidator.validate(ticket, casProperties.getServerName());
            // get principal, user id and attributes
            AttributePrincipal casPrincipal = casAssertion.getPrincipal();
            String username = casPrincipal.getName();
            log.debug("Validate ticket : {} in CAS server : {} to retrieve user : {}", new Object[]{
                 ticket, casProperties.getCasServerUrlPrefix(), username
            });

            Map<String, Object> attributes = casPrincipal.getAttributes();
            // refresh authentication token (user id + remember me)
            casToken.setUsername(username);
            String rememberMeAttributeName = casProperties.getRememberMeAttributeName();
            String rememberMeStringValue = (String)attributes.get(rememberMeAttributeName);
            boolean isRemembered = rememberMeStringValue != null && Boolean.parseBoolean(rememberMeStringValue);
            if (isRemembered) {
                casToken.setRememberMe(true);
            }
            // create simple authentication info
            List<Object> principals = CollectionUtils.asList(username, attributes);
            PrincipalCollection principalCollection = new SimplePrincipalCollection(principals, getName());
            return new SimpleAuthenticationInfo(principalCollection, ticket);
            
        } catch (TicketValidationException e) { 
            throw new CasAuthenticationException("Unable to validate ticket [" + ticket + "]", e);
        }
        
    }
    
    /**
     * Retrieves the AuthorizationInfo for the given principals (the CAS previously authenticated user : id + attributes).
     * 
     * @param principals the primary identifying principals of the AuthorizationInfo that should be retrieved.
     * @return the AuthorizationInfo associated with this principals.
     */
    @Override
    @SuppressWarnings("unchecked")
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // retrieve user information
        SimplePrincipalCollection principalCollection = (SimplePrincipalCollection) principals;
        List<Object> listPrincipals = principalCollection.asList();
        Map<String, String> attributes = (Map<String, String>) listPrincipals.get(1);
        // create simple authorization info
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        // add default roles
        addRoles(simpleAuthorizationInfo, split(defaultRoles));
        // add default permissions
        addPermissions(simpleAuthorizationInfo, split(defaultPermissions));
        // get roles from attributes
        List<String> attributeNames = split(roleAttributeNames);
        for (String attributeName : attributeNames) {
            String value = attributes.get(attributeName);
            addRoles(simpleAuthorizationInfo, split(value));
        }
        // get permissions from attributes
        attributeNames = split(permissionAttributeNames);
        for (String attributeName : attributeNames) {
            String value = attributes.get(attributeName);
            addPermissions(simpleAuthorizationInfo, split(value));
        }
        return simpleAuthorizationInfo;
    }
    
    /**
     * Split a string into a list of not empty and trimmed strings, delimiter is a comma.
     * 
     * @param s the input string
     * @return the list of not empty and trimmed strings
     */
    private List<String> split(String s) {
        List<String> list = new ArrayList<String>();
        String[] elements = StringUtils.split(s, ',');
        if (elements != null && elements.length > 0) {
            for (String element : elements) {
                if (StringUtils.hasText(element)) {
                    list.add(element.trim());
                }
            }
        }
        return list;
    }
    
    /**
     * Add roles to the simple authorization info.
     * 
     * @param simpleAuthorizationInfo
     * @param roles the list of roles to add
     */
    private void addRoles(SimpleAuthorizationInfo simpleAuthorizationInfo, List<String> roles) {
        for (String role : roles) {
            simpleAuthorizationInfo.addRole(role);
        }
    }
    
    /**
     * Add permissions to the simple authorization info.
     * 
     * @param simpleAuthorizationInfo
     * @param permissions the list of permissions to add
     */
    private void addPermissions(SimpleAuthorizationInfo simpleAuthorizationInfo, List<String> permissions) {
        for (String permission : permissions) {
            simpleAuthorizationInfo.addStringPermission(permission);
        }
    }

    public String getDefaultRoles() {
        return defaultRoles;
    }

    public void setDefaultRoles(String defaultRoles) {
        this.defaultRoles = defaultRoles;
    }

    public String getDefaultPermissions() {
        return defaultPermissions;
    }

    public void setDefaultPermissions(String defaultPermissions) {
        this.defaultPermissions = defaultPermissions;
    }

    public String getRoleAttributeNames() {
        return roleAttributeNames;
    }

    public void setRoleAttributeNames(String roleAttributeNames) {
        this.roleAttributeNames = roleAttributeNames;
    }

    public String getPermissionAttributeNames() {
        return permissionAttributeNames;
    }

    public void setPermissionAttributeNames(String permissionAttributeNames) {
        this.permissionAttributeNames = permissionAttributeNames;
    }

	public ShiroCasProperties getCasProperties() {
		return casProperties;
	}

	public void setCasProperties(ShiroCasProperties casProperties) {
		this.casProperties = casProperties;
	}
    
}
