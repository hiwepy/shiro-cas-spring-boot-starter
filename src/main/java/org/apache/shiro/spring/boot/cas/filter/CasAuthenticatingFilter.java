package org.apache.shiro.spring.boot.cas.filter;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthenticationFailureHandler;
import org.apache.shiro.biz.authc.AuthenticationSuccessHandler;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.spring.boot.cas.token.CasToken;
import org.apache.shiro.spring.boot.utils.RemoteAddrUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.jasig.cas.client.Protocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CasAuthenticatingFilter extends AuthenticatingFilter {

	private static Logger logger = LoggerFactory.getLogger(CasAuthenticatingFilter.class);
    
    // the name of the parameter service ticket in url (i.e. ticket)
    private static final String TICKET_PARAMETER = Protocol.CAS2.getArtifactParameterName();
	
    // the url where the application is redirected if the CAS service ticket validation failed (example : /mycontextpatch/cas_error.jsp)
    private String failureUrl;
    
    /** Login Listener */
	private List<LoginListener> loginListeners;
	/** Authentication Success Handler */
	private List<AuthenticationSuccessHandler> successHandlers;
	/** Authentication Failure Handler */
	private List<AuthenticationFailureHandler> failureHandlers;
    
	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		String ticket = httpRequest.getParameter(TICKET_PARAMETER);
		CasToken token = new CasToken(RemoteAddrUtils.getRemoteAddr(httpRequest));
		if(StringUtils.hasText(ticket)) {
			token.setTicket(ticket);
		}
		token.setUsername(httpRequest.getRemoteUser());
		return token;
	}

	/**
     * Execute login by creating {@link #createToken(javax.servlet.ServletRequest, javax.servlet.ServletResponse) token} and logging subject
     * with this token.
     * 
     * @param request the incoming request
     * @param response the outgoing response
     * @throws Exception if there is an error processing the request.
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }
    
    /**
     * Returns <code>false</code> to always force authentication (user is never considered authenticated by this filter).
     * 
     * @param request the incoming request
     * @param response the outgoing response
     * @param mappedValue the filter-specific config value mapped to this filter in the URL rules mappings.
     * @return <code>false</code>
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        return false;
    }
    
    /**
     * If login has been successful, redirect user to the original protected url.
     * 
     * @param token the token representing the current authentication
     * @param subject the current authenticated subjet
     * @param request the incoming request
     * @param response the outgoing response
     * @throws Exception if there is an error processing the request.
     */
    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
                                     ServletResponse response) throws Exception {
        
        // Login Listener
 		if(getLoginListeners() != null && getLoginListeners().size() > 0){
 			for (LoginListener loginListener : getLoginListeners()) {
 				loginListener.onSuccess(token, subject, request, response);
 			}
 		}
 		
 		if (CollectionUtils.isEmpty(getSuccessHandlers())) {
 			issueSuccessRedirect(request, response);
 		} else {
 			boolean isMatched = false;
 			for (AuthenticationSuccessHandler successHandler : getSuccessHandlers()) {

 				if (successHandler != null && successHandler.supports(token)) {
 					successHandler.onAuthenticationSuccess(token, request, response, subject);
 					isMatched = true;
 					break;
 				}
 			}
 			if (!isMatched) {
 				issueSuccessRedirect(request, response);
 			}
 		}
         
        //we handled the success , prevent the chain from continuing:
        return false;
    }
    
    /**
     * If login has failed, redirect user to the CAS error page (no ticket or ticket validation failed) except if the user is already
     * authenticated, in which case redirect to the default success url.
     * 
     * @param token the token representing the current authentication
     * @param e the current authentication exception
     * @param request the incoming request
     * @param response the outgoing response
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
                                     ServletResponse response) {
    	
        if (logger.isDebugEnabled()) {
            logger.debug( "Authentication exception", e );
        }
        
        // Login Listener
 		if(getLoginListeners() != null && getLoginListeners().size() > 0){
 			for (LoginListener loginListener : getLoginListeners()) {
 				loginListener.onFailure(token, e, request, response);
 			}
 		}
 		
 		logger.error("Host {} Authentication Failure : {}", getHost(request), e.getMessage());
		
		if (CollectionUtils.isEmpty(failureHandlers)) {
			// is user authenticated or in remember me mode ?
	        Subject subject = getSubject(request, response);
	        if (subject.isAuthenticated() || subject.isRemembered()) {
	            try {
	                issueSuccessRedirect(request, response);
	            } catch (Exception ex) {
	                logger.error("Cannot redirect to the default success url", ex);
	            }
	        } else {
	            try {
	                WebUtils.issueRedirect(request, response, failureUrl);
	            } catch (IOException ex) {
	                logger.error("Cannot redirect to failure url : {}", failureUrl, ex);
	            }
	        }
		} else {
			boolean isMatched = false;
			for (AuthenticationFailureHandler failureHandler : failureHandlers) {

				if (failureHandler != null && failureHandler.supports(e)) {
					failureHandler.onAuthenticationFailure(token, request, response, e);
					isMatched = true;
					break;
				}
			}
			if (!isMatched) {
				// is user authenticated or in remember me mode ?
		        Subject subject = getSubject(request, response);
		        if (subject.isAuthenticated() || subject.isRemembered()) {
		            try {
		                issueSuccessRedirect(request, response);
		            } catch (Exception ex) {
		                logger.error("Cannot redirect to the default success url", ex);
		            }
		        } else {
		            try {
		                WebUtils.issueRedirect(request, response, failureUrl);
		            } catch (IOException ex) {
		                logger.error("Cannot redirect to failure url : {}", failureUrl, ex);
		            }
		        }
			}
		}
	 
		// Login failed, let the request continue to process the response message in the specific business logic
		return false;
    }
    
    public void setFailureUrl(String failureUrl) {
        this.failureUrl = failureUrl;
    }

	public List<LoginListener> getLoginListeners() {
		return loginListeners;
	}

	public void setLoginListeners(List<LoginListener> loginListeners) {
		this.loginListeners = loginListeners;
	}
	
    public List<AuthenticationSuccessHandler> getSuccessHandlers() {
		return successHandlers;
	}

	public void setSuccessHandlers(List<AuthenticationSuccessHandler> successHandlers) {
		this.successHandlers = successHandlers;
	}

	public List<AuthenticationFailureHandler> getFailureHandlers() {
		return failureHandlers;
	}

	public void setFailureHandlers(List<AuthenticationFailureHandler> failureHandlers) {
		this.failureHandlers = failureHandlers;
	}
}
