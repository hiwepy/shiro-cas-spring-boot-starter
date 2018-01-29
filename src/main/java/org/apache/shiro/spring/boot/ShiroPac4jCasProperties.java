package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.cas.CasClientProperties;
import org.pac4j.cas.authorization.DefaultCasAuthorizationGenerator;
import org.pac4j.cas.config.CasProtocol;
import org.pac4j.core.client.Clients;
import org.pac4j.core.context.DefaultAuthorizers;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.Pac4jConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(ShiroPac4jCasProperties.PREFIX)
public class ShiroPac4jCasProperties extends CasClientProperties {

	public static final String PREFIX = "shiro.pac4j";

	/**
	 * Enable Shiro Pac4j.
	 */
	private boolean enabled = false;
	
	/** 认证IP正则表达式：可实现IP访问限制 */
    private String allowedIpRegexpPattern;
    
    private String[] allowedHttpMethods;
    
	/** The Name of Client. */
	private String clientName;
	/** The protocol of the CAS Client. */
	private CasProtocol casProtocol = CasProtocol.CAS20_PROXY;
	
	/** Defines the location of the client callback URL, i.e. https://localhost:8080/myapp/callback */
	private String callbackUrl;
	/** Specifies the name of the request parameter on where to find the clientName (i.e. client_name). */
	private String clientParameterName = Clients.DEFAULT_CLIENT_NAME_PARAMETER;
	
	/** default name of the CAS attribute for remember me authentication (CAS 3.4.10+) */
    private String rememberMeAttributeName = DefaultCasAuthorizationGenerator.DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME;
    
    /** CasClient */
    private String casClientName = "CasClient";
    
    /** DirectCasClient */
    
    private boolean directCasClient = false;
    private String directCasClientName = "DirectCasClient";
    
    /** DirectCasProxyClient */
    
    private boolean directCasProxyClient = false;
    private String directCasProxyClientName = "DirectCasProxyClient";
    
    /** CasRestBasicAuthClient */
    
    private boolean casRestBasicAuthClient = false;
    private String casRestBasicAuthClientName = "RestBasicAuthClient";
    private String headerName = HttpConstants.AUTHORIZATION_HEADER;
    private String prefixHeader = HttpConstants.BASIC_HEADER_PREFIX;
    
    /** CasRestFormClient */
    
    private boolean casRestFormClient = false;
    private String casRestFormClientName = "RestFormClient";
    private String usernameParameterName = Pac4jConstants.USERNAME;
    private String passwordParameterName = Pac4jConstants.PASSWORD;
    
    /** SecurityFilter */
    
    /** List of clients for authentication. 启用认证的客户端类型 */
    private String clients;
    /** 
     * List of authorizers. 可指定多个，通,分割 ; 每个名称对应一个实现类，除了默认的实现，也可自己定义实现 <br/>
     * @see org.pac4j.core.context.DefaultAuthorizers <br/>
     * @see org.pac4j.core.authorization.checker.DefaultAuthorizationChecker <br/>
     * <table style="border-collapse: collapse; border: 1px; width: 100%; table-layout: fixed;" class="aa" cellspacing="0" cellpadding="0" border="1">
	 *	  <tbody>
	 *	  	<tr>
	 *			<td style="padding: 0cm 5.4pt 0cm 5.4pt; width: 150px;">
	 *			<p class="MsoNormal">Authorizer名称</p>
	 *			</td>
	 *			<td style="padding: 0cm 5.4pt 0cm 5.4pt; ">
	 *			<p class="MsoNormal">Authorizer实现类</p>
	 *			</td>
	 *			<td style="padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">说明（括号里的表示备注）</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal"><strong>身份验证相关的</strong></p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">&nbsp;</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">&nbsp;</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">allowAjaxRequests</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.CorsAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">Define how the CORS requests are authorized.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">csrf</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.csrf.CsrfAuthorizer</p>
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.csrf.CsrfTokenGeneratorAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">Authorizer that checks CSRF tokens.</p>
	 *			<p class="MsoNormal">Authorizer which creates a new CSRF token and adds it as a request attribute and as a cookie (AngularJS).</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">csrfCheck</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.csrf.CsrfAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">Authorizer that checks CSRF tokens.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">csrfToken</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.csrf.CsrfTokenGeneratorAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">Authorizer which creates a new CSRF token and adds it as a request attribute and as a cookie (AngularJS).</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">hsts</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.StrictTransportSecurityHeader</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">Strict transport security header（指定https访问）.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">nocache</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.CacheControlHeader</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">Cache control header（添加不缓存策略）.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">noframe</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.XFrameOptionsHeader</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">XFrame options header（添加xframe安全策略）.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">nosniff</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.XContentTypeOptionsHeader</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">XContent type options header（添加nosniff安全策略）.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">securityheaders</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.CacheControlHeader</p>
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.XContentTypeOptionsHeader</p>
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.StrictTransportSecurityHeader</p>
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.XFrameOptionsHeader</p>
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.XSSProtectionHeader</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">Cache control header（添加不缓存策略）.</p>
	 *			<p class="MsoNormal">XContent type options header（添加nosniff安全策略）.</p>
	 *			<p class="MsoNormal">Strict transport security header（指定https访问）.</p>
	 *			<p class="MsoNormal">XFrame options header（添加xframe安全策略）.</p>
	 *			<p class="MsoNormal">XSS protection header（添加xss安全策略）.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">xssprotection</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.XSSProtectionHeader</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">XSS protection header（添加xss安全头控制）.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">method</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.CheckHttpMethodAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">Checks the HTTP method（添加请求方式检查策略）.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal"><strong>授权相关的</strong></p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">&nbsp;</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">&nbsp;</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">isAnonymous</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.IsAnonymousAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">The user must be anonymous. To protect resources like a login page.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">isAuthenticated</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.IsAuthenticatedAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">The user must be authenticated. This authorizer should never be necessary unless using the org.pac4j.core.client.direct.AnonymousClient.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">isFullyAuthenticated</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.IsFullyAuthenticatedAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">The user must be fully authenticated (not remembered).</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">isIPAuthenticated</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.http.authorization.authorizer.IpRegexpAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">Authorizes users based on their IP and a regexp pattern.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">isRemembered</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.pac4j.core.authorization.authorizer.IsRememberedAuthorizer</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">The user must be authenticated and remembered.</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal"><strong>其他</strong></p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">&nbsp;</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">&nbsp;</p>
	 *			</td>
	 *		</tr>
	 *		<tr>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">noSessionCreation</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">org.apache.shiro.web.filter.session</p>
	 *			<p class="MsoNormal">.NoSessionCreationFilter</p>
	 *			</td>
	 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
	 *			<p class="MsoNormal">不创建会话拦截器，调用 subject.getSession(false)不会有什么问题，但是如果 subject.getSession(true)将抛出 DisabledSessionException异常；</p>
	 *			</td>
	 *		</tr>
	 *	  </tbody>
	 * </table>
     */
    private String authorizers = DefaultAuthorizers.CSRF;
    private String matchers;
    
    /** Whether multiple profiles should be kept . 默认 false*/
    private boolean multiProfile = false;

    /** SecurityFilter */
    
    /** Pattern that logout urls must match（注销登录路径规则，用于匹配登录请求操作）*/
    private String logoutUrlPattern;
    /** Whether the application logout must be performed（是否注销本地应用身份认证）. 默认 true*/
    private boolean localLogout = true;
    /** Whether the centralLogout must be performed（是否注销统一身份认证）. 默认 true*/
    private boolean centralLogout = true;
    
    
	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getAllowedIpRegexpPattern() {
		return allowedIpRegexpPattern;
	}

	public void setAllowedIpRegexpPattern(String allowedIpRegexpPattern) {
		this.allowedIpRegexpPattern = allowedIpRegexpPattern;
	}

	public String[] getAllowedHttpMethods() {
		return allowedHttpMethods;
	}

	public void setAllowedHttpMethods(String[] allowedHttpMethods) {
		this.allowedHttpMethods = allowedHttpMethods;
	}

	public String getClientName() {
		return clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

	public CasProtocol getCasProtocol() {
		return casProtocol;
	}

	public void setCasProtocol(CasProtocol casProtocol) {
		this.casProtocol = casProtocol;
	}

	public String getCallbackUrl() {
		return callbackUrl;
	}

	public void setCallbackUrl(String callbackUrl) {
		this.callbackUrl = callbackUrl;
	}

	public String getClientParameterName() {
		return clientParameterName;
	}

	public void setClientParameterName(String clientParameterName) {
		this.clientParameterName = clientParameterName;
	}

	public String getRememberMeAttributeName() {
		return rememberMeAttributeName;
	}

	public void setRememberMeAttributeName(String rememberMeAttributeName) {
		this.rememberMeAttributeName = rememberMeAttributeName;
	}
	
	public String getCasClientName() {
		return casClientName;
	}

	public void setCasClientName(String casClientName) {
		this.casClientName = casClientName;
	}

	public boolean isDirectCasClient() {
		return directCasClient;
	}

	public void setDirectCasClient(boolean directCasClient) {
		this.directCasClient = directCasClient;
	}

	public String getDirectCasClientName() {
		return directCasClientName;
	}

	public void setDirectCasClientName(String directCasClientName) {
		this.directCasClientName = directCasClientName;
	}

	public boolean isDirectCasProxyClient() {
		return directCasProxyClient;
	}

	public void setDirectCasProxyClient(boolean directCasProxyClient) {
		this.directCasProxyClient = directCasProxyClient;
	}

	public String getDirectCasProxyClientName() {
		return directCasProxyClientName;
	}

	public void setDirectCasProxyClientName(String directCasProxyClientName) {
		this.directCasProxyClientName = directCasProxyClientName;
	}

	public boolean isCasRestBasicAuthClient() {
		return casRestBasicAuthClient;
	}

	public void setCasRestBasicAuthClient(boolean casRestBasicAuthClient) {
		this.casRestBasicAuthClient = casRestBasicAuthClient;
	}

	public String getCasRestBasicAuthClientName() {
		return casRestBasicAuthClientName;
	}

	public void setCasRestBasicAuthClientName(String casRestBasicAuthClientName) {
		this.casRestBasicAuthClientName = casRestBasicAuthClientName;
	}

	public String getHeaderName() {
		return headerName;
	}

	public void setHeaderName(String headerName) {
		this.headerName = headerName;
	}

	public String getPrefixHeader() {
		return prefixHeader;
	}

	public void setPrefixHeader(String prefixHeader) {
		this.prefixHeader = prefixHeader;
	}

	public boolean isCasRestFormClient() {
		return casRestFormClient;
	}

	public void setCasRestFormClient(boolean casRestFormClient) {
		this.casRestFormClient = casRestFormClient;
	}

	public String getCasRestFormClientName() {
		return casRestFormClientName;
	}

	public void setCasRestFormClientName(String casRestFormClientName) {
		this.casRestFormClientName = casRestFormClientName;
	}

	public String getUsernameParameterName() {
		return usernameParameterName;
	}

	public void setUsernameParameterName(String usernameParameterName) {
		this.usernameParameterName = usernameParameterName;
	}

	public String getPasswordParameterName() {
		return passwordParameterName;
	}

	public void setPasswordParameterName(String passwordParameterName) {
		this.passwordParameterName = passwordParameterName;
	}

	public String getClients() {
		return clients;
	}

	public void setClients(String clients) {
		this.clients = clients;
	}

	public String getAuthorizers() {
		return authorizers;
	}

	public void setAuthorizers(String authorizers) {
		this.authorizers = authorizers;
	}

	public String getMatchers() {
		return matchers;
	}

	public void setMatchers(String matchers) {
		this.matchers = matchers;
	}

	public boolean isMultiProfile() {
		return multiProfile;
	}

	public void setMultiProfile(boolean multiProfile) {
		this.multiProfile = multiProfile;
	}

	public String getLogoutUrlPattern() {
		return logoutUrlPattern;
	}

	public void setLogoutUrlPattern(String logoutUrlPattern) {
		this.logoutUrlPattern = logoutUrlPattern;
	}

	public boolean isLocalLogout() {
		return localLogout;
	}

	public void setLocalLogout(boolean localLogout) {
		this.localLogout = localLogout;
	}

	public boolean isCentralLogout() {
		return centralLogout;
	}

	public void setCentralLogout(boolean centralLogout) {
		this.centralLogout = centralLogout;
	}
	

}
