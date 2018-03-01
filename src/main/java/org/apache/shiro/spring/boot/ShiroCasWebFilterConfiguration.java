package org.apache.shiro.spring.boot;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.biz.realm.PrincipalRealmListener;
import org.apache.shiro.biz.web.filter.authc.LoginListener;
import org.apache.shiro.biz.web.filter.authc.LogoutListener;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.boot.ShiroCasProperties.CaMode;
import org.apache.shiro.spring.boot.cas.ShiroCasFilterFactoryBean;
import org.apache.shiro.spring.boot.cas.filter.CasAuthenticatingFilter;
import org.apache.shiro.spring.boot.cas.filter.CasLogoutFilter;
import org.apache.shiro.spring.boot.cas.principal.CasPrincipalRepository;
import org.apache.shiro.spring.boot.cas.realm.CasInternalAuthorizingRealm;
import org.apache.shiro.spring.boot.utils.CasUrlUtils;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.authentication.Saml11AuthenticationFilter;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.util.AssertionThreadLocalFilter;
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter;
import org.jasig.cas.client.validation.Cas10TicketValidationFilter;
import org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter;
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter;
import org.jasig.cas.client.validation.Saml11TicketValidationFilter;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

/**
 * 默认拦截器
 * <p>Shiro内置了很多默认的拦截器，比如身份验证、授权等相关的。默认拦截器可以参考org.apache.shiro.web.filter.mgt.DefaultFilter中的枚举拦截器：&nbsp;&nbsp;</p>
 * <table style="border-collapse: collapse; border: 1px; width: 100%; table-layout: fixed;" class="aa" cellspacing="0" cellpadding="0" border="1">
 *	  <tbody>
 *	  	<tr>
 *			<td style="padding: 0cm 5.4pt 0cm 5.4pt; width: 150px;">
 *			<p class="MsoNormal">默认拦截器名</p>
 *			</td>
 *			<td style="padding: 0cm 5.4pt 0cm 5.4pt; width: 215px;">
 *			<p class="MsoNormal">拦截器类</p>
 *			</td>
 *			<td style="padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">说明（括号里的表示默认值）</p>
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
 *			<p class="MsoNormal">authc</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authc</p>
 *			<p class="MsoNormal">.FormAuthenticationFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">基于表单的拦截器；如“/**=authc”，如果没有登录会跳到相应的登录页面登录；主要属性：usernameParam：表单提交的用户名参数名（ username）； &nbsp;passwordParam：表单提交的密码参数名（password）； rememberMeParam：表单提交的密码参数名（rememberMe）；&nbsp; loginUrl：登录页面地址（/login.jsp）；successUrl：登录成功后的默认重定向地址； failureKeyAttribute：登录失败后错误信息存储key（shiroLoginFailure）；</p>
 *			</td>
 *		</tr>
 *		<tr>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">authcBasic</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authc</p>
 *			<p class="MsoNormal">.BasicHttpAuthenticationFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">Basic HTTP身份验证拦截器，主要属性： applicationName：弹出登录框显示的信息（application）；</p>
 *			</td>
 *		</tr>
 *		<tr>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">logout</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authc</p>
 *			<p class="MsoNormal">.LogoutFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">退出拦截器，主要属性：redirectUrl：退出成功后重定向的地址（/）;示例“/logout=logout”</p>
 *			</td>
 *		</tr>
 *		<tr>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">user</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authc</p>
 *			<p class="MsoNormal">.UserFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">用户拦截器，用户已经身份验证/记住我登录的都可；示例“/**=user”</p>
 *			</td>
 *		</tr>
 *		<tr>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">anon</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authc</p>
 *			<p class="MsoNormal">.AnonymousFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">匿名拦截器，即不需要登录即可访问；一般用于静态资源过滤；示例“/static/**=anon”</p>
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
 *			<p class="MsoNormal">roles</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authz</p>
 *			<p class="MsoNormal">.RolesAuthorizationFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">角色授权拦截器，验证用户是否拥有所有角色；主要属性： loginUrl：登录页面地址（/login.jsp）；unauthorizedUrl：未授权后重定向的地址；示例“/admin/**=roles[admin]”</p>
 *			</td>
 *		</tr>
 *		<tr>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">perms</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authz</p>
 *			<p class="MsoNormal">.PermissionsAuthorizationFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">权限授权拦截器，验证用户是否拥有所有权限；属性和roles一样；示例“/user/**=perms["user:create"]”</p>
 *			</td>
 *		</tr>
 *		<tr>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">port</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authz</p>
 *			<p class="MsoNormal">.PortFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">端口拦截器，主要属性：port（80）：可以通过的端口；示例“/test= port[80]”，如果用户访问该页面是非80，将自动将请求端口改为80并重定向到该80端口，其他路径/参数等都一样</p>
 *			</td>
 *		</tr>
 *		<tr>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">rest</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authz</p>
 *			<p class="MsoNormal">.HttpMethodPermissionFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">rest风格拦截器，自动根据请求方法构建权限字符串（GET=read, POST=create,PUT=update,DELETE=delete,HEAD=read,TRACE=read,OPTIONS=read, MKCOL=create）构建权限字符串；示例“/users=rest[user]”，会自动拼出“user:read,user:create,user:update,user:delete”权限字符串进行权限匹配（所有都得匹配，isPermittedAll）；</p>
 *			</td>
 *		</tr>
 *		<tr>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">ssl</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">org.apache.shiro.web.filter.authz</p>
 *			<p class="MsoNormal">.SslFilter</p>
 *			</td>
 *			<td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 *			<p class="MsoNormal">SSL拦截器，只有请求协议是https才能通过；否则自动跳转会https端口（443）；其他和port拦截器一样；</p>
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
 * 自定义Filter通过@Bean注解后，被Spring Boot自动注册到了容器的Filter chain中，这样导致的结果是，所有URL都会被自定义Filter过滤，而不是Shiro中配置的一部分URL。
 * @see https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#howto-disable-registration-of-a-servlet-or-filter
 * @see http://www.jianshu.com/p/bf79fdab9c19
 * @see https://www.cnblogs.com/wangyang108/p/5844447.html
 */
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebFilterConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = ShiroCasProperties.PREFIX, value = "enabled", havingValue = "true")
@ConditionalOnClass({AuthenticationFilter.class})
@EnableConfigurationProperties({ ShiroCasProperties.class, ShiroBizProperties.class, ServerProperties.class })
public class ShiroCasWebFilterConfiguration extends AbstractShiroWebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;
	
	@Autowired
	private ShiroCasProperties casProperties;
	@Autowired
	private ShiroBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;
	
	/**
	 * 单点登录Session监听器
	 */
	@Bean
	public ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> singleSignOutHttpSessionListener() {
		ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> registration = new ServletListenerRegistrationBean<SingleSignOutHttpSessionListener>(
				new SingleSignOutHttpSessionListener());
		registration.setOrder(1);
		return registration;
	}

	/**
	 * CAS Ticket Validation Filter </br>
	 * 该过滤器负责对Ticket的校验工作
	 */
	@Bean
	public FilterRegistrationBean ticketValidationFilter() {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setEnabled(casProperties.isEnabled()); 
		if(Protocol.CAS1.equals(casProperties.getProtocol())) {
			filterRegistration.setFilter(new Cas10TicketValidationFilter());
		}
		else if(Protocol.CAS2.equals(casProperties.getProtocol())) {
			
			filterRegistration.setFilter(new Cas20ProxyReceivingTicketValidationFilter());
			
			// Cas20ProxyReceivingTicketValidationFilter
			filterRegistration.addInitParameter(ConfigurationKeys.ACCEPT_ANY_PROXY.getName(), Boolean.toString(casProperties.isAcceptAnyProxy()));
			if(StringUtils.hasText(casProperties.getAllowedProxyChains())) {	
				filterRegistration.addInitParameter(ConfigurationKeys.ALLOWED_PROXY_CHAINS.getName(), casProperties.getAllowedProxyChains());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_OVER_POST.getName(), Boolean.toString(casProperties.isArtifactParameterOverPost()));
			if(StringUtils.hasText(casProperties.getArtifactParameterName())) {	
				filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_NAME.getName(), casProperties.getArtifactParameterName());
			}
			if(StringUtils.hasText(casProperties.getAuthenticationRedirectStrategyClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS.getName(), casProperties.getAuthenticationRedirectStrategyClass());
			}
			if(StringUtils.hasText(casProperties.getCipherAlgorithm())) {
				filterRegistration.addInitParameter(ConfigurationKeys.CIPHER_ALGORITHM.getName(), casProperties.getCipherAlgorithm());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.EAGERLY_CREATE_SESSIONS.getName(), Boolean.toString(casProperties.isEagerlyCreateSessions()));
			filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY.getName(), Boolean.toString(casProperties.isGateway()));
			if(StringUtils.hasText(casProperties.getGatewayStorageClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY_STORAGE_CLASS.getName(), casProperties.getGatewayStorageClass());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_CASE.getName(), Boolean.toString(casProperties.isIgnoreCase()));
			if(StringUtils.hasText(casProperties.getIgnorePattern())) {
				filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_PATTERN.getName(), casProperties.getIgnorePattern());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE.getName(), casProperties.getIgnoreUrlPatternType().toString());
			if(StringUtils.hasText(casProperties.getLogoutParameterName())) {
				filterRegistration.addInitParameter(ConfigurationKeys.LOGOUT_PARAMETER_NAME.getName(), casProperties.getLogoutParameterName());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.MILLIS_BETWEEN_CLEAN_UPS.getName(), Long.toString(casProperties.getMillisBetweenCleanUps()));
			if(StringUtils.hasText(casProperties.getProxyReceptorUrl())) {
				filterRegistration.addInitParameter(ConfigurationKeys.PROXY_RECEPTOR_URL.getName(), casProperties.getProxyReceptorUrl());
			}
			if(StringUtils.hasText(casProperties.getProxyCallbackUrl())) {
				filterRegistration.addInitParameter(ConfigurationKeys.PROXY_CALLBACK_URL.getName(), casProperties.getProxyCallbackUrl());
			}
			if(StringUtils.hasText(casProperties.getProxyGrantingTicketStorageClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.PROXY_GRANTING_TICKET_STORAGE_CLASS.getName(), casProperties.getProxyGrantingTicketStorageClass());
			}
			if(StringUtils.hasText(casProperties.getRelayStateParameterName())) {
				filterRegistration.addInitParameter(ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getName(), casProperties.getRelayStateParameterName());
			}
			if(StringUtils.hasText(casProperties.getRoleAttribute())) {
				filterRegistration.addInitParameter(ConfigurationKeys.ROLE_ATTRIBUTE.getName(), casProperties.getRoleAttribute());
			}
			if(StringUtils.hasText(casProperties.getSecretKey())) {
				filterRegistration.addInitParameter(ConfigurationKeys.SECRET_KEY.getName(), casProperties.getSecretKey());
			}
			if(StringUtils.hasText(casProperties.getTicketValidatorClass())) {
				filterRegistration.addInitParameter(ConfigurationKeys.TICKET_VALIDATOR_CLASS.getName(), casProperties.getTicketValidatorClass());
			}
			filterRegistration.addInitParameter(ConfigurationKeys.TOLERANCE.getName(), Long.toString(casProperties.getTolerance()));
			
		}
		else if(Protocol.CAS3.equals(casProperties.getProtocol())) {
			filterRegistration.setFilter(new Cas30ProxyReceivingTicketValidationFilter());
		}
		else if(Protocol.SAML11.equals(casProperties.getProtocol())) {
			filterRegistration.setFilter(new Saml11TicketValidationFilter());
			// Saml11TicketValidationFilter
			filterRegistration.addInitParameter(ConfigurationKeys.TOLERANCE.getName(), Long.toString(casProperties.getTolerance()));
		}
		
		// Cas10TicketValidationFilter、Cas20ProxyReceivingTicketValidationFilter、Cas30ProxyReceivingTicketValidationFilter、Saml11TicketValidationFilter
		filterRegistration.addInitParameter(ConfigurationKeys.ENCODE_SERVICE_URL.getName(), Boolean.toString(casProperties.isEncodeServiceUrl()));
		if(StringUtils.hasText(casProperties.getEncoding())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.ENCODING.getName(), casProperties.getEncoding());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.EXCEPTION_ON_VALIDATION_FAILURE.getName(), Boolean.toString(casProperties.isExceptionOnValidationFailure()));
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_LOGIN_URL.getName(), casProperties.getCasServerLoginUrl());
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_URL_PREFIX.getName(), casProperties.getCasServerUrlPrefix());
		if(StringUtils.hasText(casProperties.getHostnameVerifier())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.HOSTNAME_VERIFIER.getName(), casProperties.getHostnameVerifier());
		}
		if(StringUtils.hasText(casProperties.getHostnameVerifierConfig())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.HOSTNAME_VERIFIER_CONFIG.getName(), casProperties.getHostnameVerifierConfig());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.REDIRECT_AFTER_VALIDATION.getName(), Boolean.toString(casProperties.isRedirectAfterValidation()));
		//filterRegistration.addInitParameter(ConfigurationKeys.RENEW.getName(), Boolean.toString(properties.isRenew()));
		if(StringUtils.hasText(casProperties.getServerName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVER_NAME.getName(), casProperties.getServerName());
		} else if(StringUtils.hasText(casProperties.getService())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVICE.getName(), casProperties.getService());
		}
		if(StringUtils.hasText(casProperties.getSslConfigFile())) {
			filterRegistration.addInitParameter(ConfigurationKeys.SSL_CONFIG_FILE.getName(), casProperties.getSslConfigFile());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.USE_SESSION.getName(), Boolean.toString(casProperties.isUseSession()));
		
		
		filterRegistration.addUrlPatterns(casProperties.getTicketValidationFilterUrlPatterns());
		filterRegistration.setOrder(3);
	    return filterRegistration;
	}
	
	/**
	 * CAS Authentication Filter </br>
	 * 该过滤器负责用户的认证工作
	 */
	@Bean
	public FilterRegistrationBean authenticationFilter() {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		if (Protocol.SAML11.equals(casProperties.getProtocol())) {
			filterRegistration.setFilter(new Saml11AuthenticationFilter());
		} else {
			filterRegistration.setFilter(new AuthenticationFilter());
		}
		
		if(StringUtils.hasText(casProperties.getAuthenticationRedirectStrategyClass())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS.getName(), casProperties.getAuthenticationRedirectStrategyClass());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_LOGIN_URL.getName(), casProperties.getCasServerLoginUrl());
		filterRegistration.addInitParameter(ConfigurationKeys.ENCODE_SERVICE_URL.getName(), Boolean.toString(casProperties.isEncodeServiceUrl()));
		filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY.getName(), Boolean.toString(casProperties.isGateway()));
		if(StringUtils.hasText(casProperties.getGatewayStorageClass())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.GATEWAY_STORAGE_CLASS.getName(), casProperties.getGatewayStorageClass());
		}
		if(StringUtils.hasText(casProperties.getIgnorePattern())) {
			filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_PATTERN.getName(), casProperties.getIgnorePattern());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE.getName(), casProperties.getIgnoreUrlPatternType().toString());
		//filterRegistration.addInitParameter(ConfigurationKeys.RENEW.getName(), Boolean.toString(properties.isRenew()));
		if(StringUtils.hasText(casProperties.getServerName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVER_NAME.getName(), casProperties.getServerName());
		} else if(StringUtils.hasText(casProperties.getService())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.SERVICE.getName(), casProperties.getService());
		}
		
		filterRegistration.addUrlPatterns(casProperties.getAuthenticationFilterUrlPatterns());
		filterRegistration.setOrder(4);
		return filterRegistration;
	}

	/**
	 * CAS HttpServletRequest Wrapper Filter </br>
	 * 该过滤器对HttpServletRequest请求包装， 可通过HttpServletRequest的getRemoteUser()方法获得登录用户的登录名
	 */
	@Bean
	public FilterRegistrationBean requestWrapperFilter() {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setFilter(new HttpServletRequestWrapperFilter());
		filterRegistration.setEnabled(casProperties.isEnabled()); 
		filterRegistration.addInitParameter(ConfigurationKeys.IGNORE_CASE.getName(), String.valueOf(casProperties.isIgnoreCase()));
		if(StringUtils.hasText(casProperties.getRoleAttribute())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.ROLE_ATTRIBUTE.getName(), casProperties.getRoleAttribute());
		}
		filterRegistration.addUrlPatterns(casProperties.getRequestWrapperFilterUrlPatterns());
		filterRegistration.setOrder(5);
	    return filterRegistration;
	}

	/**
	 * CAS Assertion Thread Local Filter </br>
	 * 该过滤器使得可以通过org.jasig.cas.client.util.AssertionHolder来获取用户的登录名。
	 * 比如AssertionHolder.getAssertion().getPrincipal().getName()。
	 * 这个类把Assertion信息放在ThreadLocal变量中，这样应用程序不在web层也能够获取到当前登录信息
	 */
	@Bean
	public FilterRegistrationBean assertionThreadLocalFilter() {
		FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
		filterRegistration.setFilter(new AssertionThreadLocalFilter());
		filterRegistration.setEnabled(casProperties.isEnabled());
		filterRegistration.addUrlPatterns(casProperties.getAssertionThreadLocalFilterUrlPatterns());
		filterRegistration.setOrder(6);
		return filterRegistration;
	}
	
	/**
	 * 登录监听：实现该接口可监听账号登录失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 */
	@Bean("loginListeners")
	public List<LoginListener> loginListeners() {

		List<LoginListener> loginListeners = new ArrayList<LoginListener>();
		
		Map<String, LoginListener> beansOfType = getApplicationContext().getBeansOfType(LoginListener.class);
		if (!ObjectUtils.isEmpty(beansOfType)) {
			Iterator<Entry<String, LoginListener>> ite = beansOfType.entrySet().iterator();
			while (ite.hasNext()) {
				loginListeners.add(ite.next().getValue());
			}
		}
		
		return loginListeners;
	}
	
	/**
	 * Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 */
	@Bean("realmListeners")
	public List<PrincipalRealmListener> realmListeners() {

		List<PrincipalRealmListener> realmListeners = new ArrayList<PrincipalRealmListener>();
		
		Map<String, PrincipalRealmListener> beansOfType = getApplicationContext().getBeansOfType(PrincipalRealmListener.class);
		if (!ObjectUtils.isEmpty(beansOfType)) {
			Iterator<Entry<String, PrincipalRealmListener>> ite = beansOfType.entrySet().iterator();
			while (ite.hasNext()) {
				realmListeners.add(ite.next().getValue());
			}
		}
		
		return realmListeners;
	}
	
	/**
	 * 注销监听：实现该接口可监听账号注销失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 */
	@Bean("logoutListeners")
	public List<LogoutListener> logoutListeners() {

		List<LogoutListener> logoutListeners = new ArrayList<LogoutListener>();
		
		Map<String, LogoutListener> beansOfType = getApplicationContext().getBeansOfType(LogoutListener.class);
		if (!ObjectUtils.isEmpty(beansOfType)) {
			Iterator<Entry<String, LogoutListener>> ite = beansOfType.entrySet().iterator();
			while (ite.hasNext()) {
				logoutListeners.add(ite.next().getValue());
			}
		}
		
		return logoutListeners;
	}
	
	/**
	 * 系统登录注销过滤器；默认：org.apache.shiro.spring.boot.cas.filter.CasLogoutFilter
	 */
	@Bean("logout")
	@ConditionalOnMissingBean(name = "logout")
	public FilterRegistrationBean logoutFilter(List<LogoutListener> logoutListeners){
		
		FilterRegistrationBean registration = new FilterRegistrationBean(); 
		CasLogoutFilter logoutFilter = new CasLogoutFilter();
		
		//登录注销后的重定向地址：直接进入登录页面
		if( CaMode.sso.compareTo(casProperties.getCaMode()) == 0) {
			logoutFilter.setCasLogin(true);
			logoutFilter.setRedirectUrl(CasUrlUtils.constructLogoutRedirectUrl(casProperties, serverProperties.getServlet().getContextPath(), bizProperties.getLoginUrl()));
		} else {
			logoutFilter.setRedirectUrl(bizProperties.getLoginUrl());
		}
		registration.setFilter(logoutFilter);
		//注销监听：实现该接口可监听账号注销失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		logoutFilter.setLogoutListeners(logoutListeners);
	    
	    registration.setEnabled(false); 
	    return registration;
	}
	
	@Bean("cas")
	@ConditionalOnMissingBean(name = "cas")
	public FilterRegistrationBean casFilter(ShiroCasProperties properties){
		FilterRegistrationBean registration = new FilterRegistrationBean(); 
		CasAuthenticatingFilter casSsoFilter = new CasAuthenticatingFilter();
		casSsoFilter.setFailureUrl(bizProperties.getFailureUrl());
		casSsoFilter.setSuccessUrl(bizProperties.getSuccessUrl());
		registration.setFilter(casSsoFilter);
	    registration.setEnabled(false); 
	    return registration;
	}
	
	@Bean
	public Realm casRealm(@Qualifier("casRepository") CasPrincipalRepository repository,
			List<PrincipalRealmListener> realmsListeners) {
		
		CasInternalAuthorizingRealm casRealm = new CasInternalAuthorizingRealm(casProperties);
		//认证账号信息提供实现：认证信息、角色信息、权限信息；业务系统需要自己实现该接口
		casRealm.setRepository(repository);
		//凭证匹配器：该对象主要做密码校验
		casRealm.setCredentialsMatcher(new AllowAllCredentialsMatcher());
		//Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
		casRealm.setRealmsListeners(realmsListeners);
		//缓存相关的配置：采用提供的默认配置即可
		casRealm.setCachingEnabled(bizProperties.isCachingEnabled());
		//认证缓存配置
		casRealm.setAuthenticationCachingEnabled(bizProperties.isAuthenticationCachingEnabled());
		casRealm.setAuthenticationCacheName(bizProperties.getAuthenticationCacheName());
		//授权缓存配置
		casRealm.setAuthorizationCachingEnabled(bizProperties.isAuthorizationCachingEnabled());
		casRealm.setAuthorizationCacheName(bizProperties.getAuthorizationCacheName());
		
		return casRealm;
	}
	
	@Bean
    @Override
    protected ShiroFilterFactoryBean shiroFilterFactoryBean() {
		
		ShiroFilterFactoryBean filterFactoryBean = new ShiroCasFilterFactoryBean();
        
        //登录地址：会话不存在时访问的地址
  		filterFactoryBean.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(casProperties, serverProperties.getServlet().getContextPath(), casProperties.getServerCallbackUrl()));
  		//系统主页：登录成功后跳转路径
  		filterFactoryBean.setSuccessUrl(bizProperties.getSuccessUrl());
  		//异常页面：无权限时的跳转路径
  		filterFactoryBean.setUnauthorizedUrl(bizProperties.getUnauthorizedUrl());
      
  		//必须设置 SecurityManager
 		filterFactoryBean.setSecurityManager(securityManager);
 		//拦截规则
 		filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
      
 		return filterFactoryBean;
        
    }

	@Bean(name = "filterShiroFilterRegistrationBean")
    protected FilterRegistrationBean filterShiroFilterRegistrationBean() throws Exception {

        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter((AbstractShiroFilter) shiroFilterFactoryBean().getObject());
        filterRegistrationBean.setOrder(Ordered.LOWEST_PRECEDENCE);

        return filterRegistrationBean;
    }
    
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}
	
}
