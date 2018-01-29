package org.apache.shiro.spring.boot.cas;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jasig.cas.client.Protocol;

public class CasClientProperties{

	// default name of the CAS attribute for remember me authentication (CAS 3.4.10+)
    public static final String DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";
	
	/** DEFAULT,JNDI,WEB_XML,PROPERTY_FILE,SYSTEM_PROPERTIES */
	private String configurationStrategy;
	/** Defines the location of the CAS server login URL, i.e. https://localhost:8443/cas/login */
	private String casServerLoginUrl;
	/** Defines the location of the CAS server logout URL, i.e. https://localhost:8443/cas/logout */
	private String casServerLogoutUrl;
	/** Defines the location of the CAS server rest URL, i.e. https://localhost:8443/cas/v1/tickets */
	private String casServerRestUrl;
	/** The prefix url of the CAS server. i.e.https://localhost:8443/cas */
	private String casServerUrlPrefix;
    /** Defaults to true */
	private boolean eagerlyCreateSessions = true;
    /** Specifies whether any proxy is OK. Defaults to false. */
	private boolean acceptAnyProxy = false;
	/**
	 * Specifies the proxy chain. 
	 * Each acceptable proxy chain should include a space-separated list of URLs (for exact match) or regular expressions of URLs (starting by the ^ character). 
	 * Each acceptable proxy chain should appear on its own line.
	 */
	private String allowedProxyChains;
	/** Specifies the name of the request parameter on where to find the artifact (i.e. ticket). */
	private String artifactParameterName = "ticket";
	private boolean artifactParameterOverPost = false;
	/** The Url Patterns of AssertionThreadLocalFilter. */
	private String[] assertionThreadLocalFilterUrlPatterns = new String[] { "/*" };
	/** The class name of the component to decide how to handle authn redirects to CAS */
	private String authenticationRedirectStrategyClass;
	/** The Url Patterns of AuthenticationFilter. */
	private String[] authenticationFilterUrlPatterns = new String[] { "/*" };
	/** The algorithm used by the proxyGrantingTicketStorageClass if it supports encryption. Defaults to DESede */
	private String cipherAlgorithm;
	/** Default url to redirect to, in case no erorr matches are found. */
	private String defaultErrorRedirectPage;
	/** Whether Enable Cas. */
	private boolean enabled = false;
	/** Specifies the encoding charset the client should use */
	private String encoding = "UTF-8";
	/** Whether Enable ErrorRedirectFilter. */
	private boolean errorRedirect = false;
	/** The Url to redirect to, find the path by Fully qualified exception name , i.e. java.lang.Exception . */
	private Map<String /* Class Name */, String /* Redirect Page Path */> errorRedirectMappings = new LinkedHashMap<String, String>();
	/** The Url Patterns of ErrorRedirectFilter. */
	private String[] errorRedirectFilterUrlPatterns = new String[] { "/*" };
	/** Whether the client should auto encode the service url. Defaults to true */
	private boolean encodeServiceUrl = true;
	/** Whether to throw an exception or not on ticket validation failure. Defaults to true. */
	private boolean exceptionOnValidationFailure = true;
	/** the url where the application is redirected if the CAS service ticket validation failed (example : /mycontextpatch/cas_error.jsp) */
	private String failureUrl;
	/** Specifies whether gateway=true should be sent to the CAS server. Valid values are either true/false (or no value at all) */
	private boolean gateway = false;
	/** The storage class used to record gateway requests */
	private String gatewayStorageClass;
	/** Hostname verifier class name, used when making back-channel calls */
	private String hostnameVerifier;
	private String hostnameVerifierConfig;
	/** Whether role checking should ignore case. Defaults to false. */
	private boolean ignoreCase = false;
	/** Defines the url pattern to ignore, when intercepting authentication requests. */
	private String ignorePattern;
	/** Defines the type of the pattern specified. Defaults to REGEX. Other types are CONTAINS, EXACT. */
	private String ignoreUrlPatternType = "REGEX";

	private boolean ignoreInitConfiguration = false;
	/** Defaults to logoutRequest */
	private String logoutParameterName;
	/** Startup delay for the cleanup task to remove expired tickets from the storage. Defaults to 60000 msec */
	private long millisBetweenCleanUps = 60000L;
	/** The protocol of the CAS Client. */
	private Protocol protocol = Protocol.CAS2;
	/** The callback URL to provide the CAS server to accept Proxy Granting Tickets. */
	private String proxyCallbackUrl;
	/**
	 * The URL to watch for PGTIOU/PGT responses from the CAS server. 
	 * Should be defined from the root of the context. 
	 * For example, if your application is deployed in /cas-client-app and 
	 * you want the proxy receptor URL to be /cas-client-app/my/receptor 
	 * you need to configure proxyReceptorUrl to be /my/receptor.
	 */
	private String proxyReceptorUrl;
	/** Specify an implementation of the ProxyGrantingTicketStorage class that has a no-arg constructor. */
	private String proxyGrantingTicketStorageClass;
	/** The Url Patterns of HttpServletRequestWrapperFilter. */
	private String[] requestWrapperFilterUrlPatterns = new String[] { "/*" };
	/** Whether to redirect to the same URL after ticket validation, but without the ticket in the parameter. Defaults to true. */
	private boolean redirectAfterValidation = true;
	/**
	 * Specifies whether renew=true should be sent to the CAS server. 
	 * Valid values are either true/false (or no value at all). 
	 * Note that renew cannot be specified as local init-param setting..
	 */
	private boolean renew = false;
	/** Name of parameter containing the state of the CAS server webflow. */
	private String relayStateParameterName;
	/** Used to determine the principal role. */
	private String roleAttribute;
	/** default name of the CAS attribute for remember me authentication (CAS 3.4.10+) */
    private String rememberMeAttributeName = DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME;
	/** The secret key used by the proxyGrantingTicketStorageClass if it supports encryption. */
	private String secretKey;
	/** Defines the location of the application cas callback URL, i.e. /callback */
	private String serverCallbackUrl;
	/**
	 * The name of the server this application is hosted on. 
	 * Service URL will be dynamically constructed using this, 
	 * i.e. https://localhost:8443 (you must include the protocol, but port is optional if it's a standard port).
	 */
	private String serverName;
	/** The service URL to send to the CAS server, i.e. https://localhost:8443/yourwebapp/index.html */
	private String service;
	/** Specifies the name of the request parameter on where to find the service (i.e. service). */
	private String serviceParameterName = "service";
	/** The Url Patterns of SingleSignOutFilter. */
	private String[] signOutFilterUrlPatterns = new String[] { "/*" };
	/**
	 * A reference to a properties file that includes SSL settings for client-side
	 * SSL config, used during back-channel calls. The configuration includes keys
	 * for protocol which defaults to SSL,keyStoreType, keyStorePath,
	 * keyStorePass,keyManagerType which defaults to SunX509 andcertificatePassword.
	 */
	private String sslConfigFile;
	/** The Url Patterns of TicketValidationFilter. */
	private String[] ticketValidationFilterUrlPatterns = new String[] { "/*" };
	/** Ticket validator class to use/create */
	private String ticketValidatorClass;
	/**
	 * The tolerance for drifting clocks when validating SAML tickets. 
	 * Note that 10 seconds should be more than enough for most environments that have NTP time synchronization. 
	 * Defaults to 1000 msec
	 */
	private long tolerance = 5000L;
	/**
	 * Whether to store the Assertion in session or not. If sessions are not used,
	 * tickets will be required for each request. Defaults to true.
	 */
	private boolean useSession = true;

	public String getConfigurationStrategy() {
		return configurationStrategy;
	}

	public void setConfigurationStrategy(String configurationStrategy) {
		this.configurationStrategy = configurationStrategy;
	}

	public String getCasServerLoginUrl() {
		return casServerLoginUrl;
	}

	public void setCasServerLoginUrl(String casServerLoginUrl) {
		this.casServerLoginUrl = casServerLoginUrl;
	}
	
	public String getCasServerLogoutUrl() {
		return casServerLogoutUrl;
	}

	public void setCasServerLogoutUrl(String casServerLogoutUrl) {
		this.casServerLogoutUrl = casServerLogoutUrl;
	}

	public String getCasServerRestUrl() {
		return casServerRestUrl;
	}

	public void setCasServerRestUrl(String casServerRestUrl) {
		this.casServerRestUrl = casServerRestUrl;
	}

	public String getCasServerUrlPrefix() {
		return casServerUrlPrefix;
	}

	public void setCasServerUrlPrefix(String casServerUrlPrefix) {
		this.casServerUrlPrefix = casServerUrlPrefix;
	}

	public boolean isEagerlyCreateSessions() {
		return eagerlyCreateSessions;
	}

	public void setEagerlyCreateSessions(boolean eagerlyCreateSessions) {
		this.eagerlyCreateSessions = eagerlyCreateSessions;
	}

	public boolean isAcceptAnyProxy() {
		return acceptAnyProxy;
	}

	public void setAcceptAnyProxy(boolean acceptAnyProxy) {
		this.acceptAnyProxy = acceptAnyProxy;
	}

	public String getAllowedProxyChains() {
		return allowedProxyChains;
	}

	public void setAllowedProxyChains(String allowedProxyChains) {
		this.allowedProxyChains = allowedProxyChains;
	}

	public String getArtifactParameterName() {
		return artifactParameterName;
	}

	public void setArtifactParameterName(String artifactParameterName) {
		this.artifactParameterName = artifactParameterName;
	}

	public boolean isArtifactParameterOverPost() {
		return artifactParameterOverPost;
	}

	public void setArtifactParameterOverPost(boolean artifactParameterOverPost) {
		this.artifactParameterOverPost = artifactParameterOverPost;
	}

	public String[] getAssertionThreadLocalFilterUrlPatterns() {
		return assertionThreadLocalFilterUrlPatterns;
	}

	public void setAssertionThreadLocalFilterUrlPatterns(String[] assertionThreadLocalFilterUrlPatterns) {
		this.assertionThreadLocalFilterUrlPatterns = assertionThreadLocalFilterUrlPatterns;
	}

	public String getAuthenticationRedirectStrategyClass() {
		return authenticationRedirectStrategyClass;
	}

	public void setAuthenticationRedirectStrategyClass(String authenticationRedirectStrategyClass) {
		this.authenticationRedirectStrategyClass = authenticationRedirectStrategyClass;
	}

	public String[] getAuthenticationFilterUrlPatterns() {
		return authenticationFilterUrlPatterns;
	}

	public void setAuthenticationFilterUrlPatterns(String[] authenticationFilterUrlPatterns) {
		this.authenticationFilterUrlPatterns = authenticationFilterUrlPatterns;
	}

	public String getCipherAlgorithm() {
		return cipherAlgorithm;
	}

	public void setCipherAlgorithm(String cipherAlgorithm) {
		this.cipherAlgorithm = cipherAlgorithm;
	}

	public String getDefaultErrorRedirectPage() {
		return defaultErrorRedirectPage;
	}

	public void setDefaultErrorRedirectPage(String defaultErrorRedirectPage) {
		this.defaultErrorRedirectPage = defaultErrorRedirectPage;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getEncoding() {
		return encoding;
	}

	public void setEncoding(String encoding) {
		this.encoding = encoding;
	}

	public boolean isErrorRedirect() {
		return errorRedirect;
	}

	public void setErrorRedirect(boolean errorRedirect) {
		this.errorRedirect = errorRedirect;
	}

	public Map<String, String> getErrorRedirectMappings() {
		return errorRedirectMappings;
	}

	public void setErrorRedirectMappings(Map<String, String> errorRedirectMappings) {
		this.errorRedirectMappings = errorRedirectMappings;
	}

	public String[] getErrorRedirectFilterUrlPatterns() {
		return errorRedirectFilterUrlPatterns;
	}

	public void setErrorRedirectFilterUrlPatterns(String[] errorRedirectFilterUrlPatterns) {
		this.errorRedirectFilterUrlPatterns = errorRedirectFilterUrlPatterns;
	}

	public boolean isEncodeServiceUrl() {
		return encodeServiceUrl;
	}

	public void setEncodeServiceUrl(boolean encodeServiceUrl) {
		this.encodeServiceUrl = encodeServiceUrl;
	}

	public boolean isExceptionOnValidationFailure() {
		return exceptionOnValidationFailure;
	}

	public void setExceptionOnValidationFailure(boolean exceptionOnValidationFailure) {
		this.exceptionOnValidationFailure = exceptionOnValidationFailure;
	}

	public String getFailureUrl() {
		return failureUrl;
	}

	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}

	public boolean isGateway() {
		return gateway;
	}

	public void setGateway(boolean gateway) {
		this.gateway = gateway;
	}

	public String getGatewayStorageClass() {
		return gatewayStorageClass;
	}

	public void setGatewayStorageClass(String gatewayStorageClass) {
		this.gatewayStorageClass = gatewayStorageClass;
	}

	public String getHostnameVerifier() {
		return hostnameVerifier;
	}

	public void setHostnameVerifier(String hostnameVerifier) {
		this.hostnameVerifier = hostnameVerifier;
	}

	public String getHostnameVerifierConfig() {
		return hostnameVerifierConfig;
	}

	public void setHostnameVerifierConfig(String hostnameVerifierConfig) {
		this.hostnameVerifierConfig = hostnameVerifierConfig;
	}

	public boolean isIgnoreCase() {
		return ignoreCase;
	}

	public void setIgnoreCase(boolean ignoreCase) {
		this.ignoreCase = ignoreCase;
	}

	public String getIgnorePattern() {
		return ignorePattern;
	}

	public void setIgnorePattern(String ignorePattern) {
		this.ignorePattern = ignorePattern;
	}

	public String getIgnoreUrlPatternType() {
		return ignoreUrlPatternType;
	}

	public void setIgnoreUrlPatternType(String ignoreUrlPatternType) {
		this.ignoreUrlPatternType = ignoreUrlPatternType;
	}

	public boolean isIgnoreInitConfiguration() {
		return ignoreInitConfiguration;
	}

	public void setIgnoreInitConfiguration(boolean ignoreInitConfiguration) {
		this.ignoreInitConfiguration = ignoreInitConfiguration;
	}

	public String getLogoutParameterName() {
		return logoutParameterName;
	}

	public void setLogoutParameterName(String logoutParameterName) {
		this.logoutParameterName = logoutParameterName;
	}

	public long getMillisBetweenCleanUps() {
		return millisBetweenCleanUps;
	}

	public void setMillisBetweenCleanUps(long millisBetweenCleanUps) {
		this.millisBetweenCleanUps = millisBetweenCleanUps;
	}

	public Protocol getProtocol() {
		return protocol;
	}

	public void setProtocol(Protocol protocol) {
		this.protocol = protocol;
	}

	public String getProxyCallbackUrl() {
		return proxyCallbackUrl;
	}

	public void setProxyCallbackUrl(String proxyCallbackUrl) {
		this.proxyCallbackUrl = proxyCallbackUrl;
	}

	public String getProxyReceptorUrl() {
		return proxyReceptorUrl;
	}

	public void setProxyReceptorUrl(String proxyReceptorUrl) {
		this.proxyReceptorUrl = proxyReceptorUrl;
	}

	public String getProxyGrantingTicketStorageClass() {
		return proxyGrantingTicketStorageClass;
	}

	public void setProxyGrantingTicketStorageClass(String proxyGrantingTicketStorageClass) {
		this.proxyGrantingTicketStorageClass = proxyGrantingTicketStorageClass;
	}

	public String[] getRequestWrapperFilterUrlPatterns() {
		return requestWrapperFilterUrlPatterns;
	}

	public void setRequestWrapperFilterUrlPatterns(String[] requestWrapperFilterUrlPatterns) {
		this.requestWrapperFilterUrlPatterns = requestWrapperFilterUrlPatterns;
	}

	public boolean isRedirectAfterValidation() {
		return redirectAfterValidation;
	}

	public void setRedirectAfterValidation(boolean redirectAfterValidation) {
		this.redirectAfterValidation = redirectAfterValidation;
	}

	public boolean isRenew() {
		return renew;
	}

	public void setRenew(boolean renew) {
		this.renew = renew;
	}

	public String getRelayStateParameterName() {
		return relayStateParameterName;
	}

	public void setRelayStateParameterName(String relayStateParameterName) {
		this.relayStateParameterName = relayStateParameterName;
	}

	public String getRoleAttribute() {
		return roleAttribute;
	}

	public void setRoleAttribute(String roleAttribute) {
		this.roleAttribute = roleAttribute;
	}
	
	public String getRememberMeAttributeName() {
		return rememberMeAttributeName;
	}

	public void setRememberMeAttributeName(String rememberMeAttributeName) {
		this.rememberMeAttributeName = rememberMeAttributeName;
	}

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	public String getServerCallbackUrl() {
		return serverCallbackUrl;
	}

	public void setServerCallbackUrl(String serverCallbackUrl) {
		this.serverCallbackUrl = serverCallbackUrl;
	}

	public String getServerName() {
		return serverName;
	}

	public void setServerName(String serverName) {
		this.serverName = serverName;
	}
	
	public String getService() {
		return service;
	}

	public void setService(String service) {
		this.service = service;
	}

	public String[] getSignOutFilterUrlPatterns() {
		return signOutFilterUrlPatterns;
	}

	public void setSignOutFilterUrlPatterns(String[] signOutFilterUrlPatterns) {
		this.signOutFilterUrlPatterns = signOutFilterUrlPatterns;
	}

	public String getSslConfigFile() {
		return sslConfigFile;
	}

	public void setSslConfigFile(String sslConfigFile) {
		this.sslConfigFile = sslConfigFile;
	}

	public String[] getTicketValidationFilterUrlPatterns() {
		return ticketValidationFilterUrlPatterns;
	}

	public void setTicketValidationFilterUrlPatterns(String[] ticketValidationFilterUrlPatterns) {
		this.ticketValidationFilterUrlPatterns = ticketValidationFilterUrlPatterns;
	}

	public String getTicketValidatorClass() {
		return ticketValidatorClass;
	}

	public void setTicketValidatorClass(String ticketValidatorClass) {
		this.ticketValidatorClass = ticketValidatorClass;
	}

	public long getTolerance() {
		return tolerance;
	}

	public void setTolerance(long tolerance) {
		this.tolerance = tolerance;
	}

	public boolean isUseSession() {
		return useSession;
	}

	public void setUseSession(boolean useSession) {
		this.useSession = useSession;
	}

	public String getServiceParameterName() {
		return serviceParameterName;
	}

	public void setServiceParameterName(String serviceParameterName) {
		this.serviceParameterName = serviceParameterName;
	}

}
