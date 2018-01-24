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
package org.apache.shiro.spring.boot.utils;

import java.net.URI;
import java.net.URL;

import org.apache.shiro.spring.boot.ShiroCasPac4jProperties;
import org.jasig.cas.client.util.URIBuilder;
import org.pac4j.cas.client.CasClient;
import org.pac4j.cas.client.direct.DirectCasClient;
import org.pac4j.cas.client.direct.DirectCasProxyClient;
import org.pac4j.cas.client.rest.CasRestBasicAuthClient;
import org.pac4j.cas.client.rest.CasRestFormClient;
import org.pac4j.cas.config.CasConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;

public class CasClientUtils {

	public static CasClient casClient(CasConfiguration configuration,ShiroCasPac4jProperties casProperties,ServerProperties serverProperties) {

		CasClient casClient = new CasClient(configuration);

		final URIBuilder builder;

		URL url = new URL(StringUtils.hasText(casProperties.getServerName()) ? casProperties.getServerName() : casProperties.getService());
		URI uri = new URI(url.getProtocol(), url.getUserInfo(), url.getHost(), url.getPort(), url.getPath(),
				url.getQuery(), null);

		if (!"https".equals(url.getProtocol()) && !"http".equals(url.getProtocol())) {
			builder = new URIBuilder(casProperties.isEncodeServiceUrl());
			builder.setScheme(request.isSecure() ? "https" : "http");
			builder.setHost(casProperties.getServerName());
		} else {
			builder = new URIBuilder(casProperties.getServerName(), casProperties.isEncodeServiceUrl());
		}

		String contextPath = StringUtils.hasText(serverProperties.getContextPath()) ? serverProperties.getContextPath() : "/";
		if (contextPath.endsWith("/")) {
			contextPath = contextPath.substring(0, contextPath.length() - 1);
		}

		StringBuilder callbackUrl = new StringBuilder(casProperties.getServerName()).append(contextPath).append("/")
				.append("callback?client_name=").append(casProperties.getClientName());

		casClient.setCallbackUrl(callbackUrl.toString());
		casClient.setName(casProperties.getClientName());

		return casClient;
	}

	public static DirectCasClient directCasClient(CasConfiguration configuration,ShiroCasPac4jProperties casProperties) {
		
		DirectCasClient casClient = new DirectCasClient();
		
		casClient.setConfiguration(configuration);
		casClient.setName(StringUtils.hasText(casProperties.getDirectCasClientName()) ? casProperties.getDirectCasClientName() : "DirectCasClient");
		
		return casClient;
	}

	public static DirectCasProxyClient directCasProxyClient(CasConfiguration configuration,ShiroCasPac4jProperties casProperties) {
		
		DirectCasProxyClient casClient = new DirectCasProxyClient();
		
		casClient.setConfiguration(configuration);
		casClient.setName(StringUtils.hasText(casProperties.getDirectCasProxyClientName()) ? casProperties.getDirectCasProxyClientName() : "DirectCasProxyClient");
		casClient.setServiceUrl(casProperties.getCasServerUrlPrefix());
		
		return casClient;
	}

	public static CasRestBasicAuthClient casRestBasicAuthClient(CasConfiguration configuration,ShiroCasPac4jProperties casProperties) {
		
		CasRestBasicAuthClient casClient = new CasRestBasicAuthClient();
		
		casClient.setConfiguration(configuration);
		casClient.setName(StringUtils.hasText(casProperties.getCasRestBasicAuthClientName()) ? casProperties.getCasRestBasicAuthClientName() : "RestBasicAuthClient");
		if(StringUtils.hasText(casProperties.getHeaderName())) {	
			casClient.setHeaderName(casProperties.getHeaderName());
		}
		if(StringUtils.hasText(casProperties.getPrefixHeader())) {	
			casClient.setPrefixHeader(casProperties.getPrefixHeader());
		}
		
		return casClient;
	}

	/**
	 * 通过rest接口可以获取tgt，获取service ticket，甚至可以获取CasProfile
	 * @return
	 */
	public static CasRestFormClient casRestFormClient(CasConfiguration configuration,ShiroCasPac4jProperties casProperties) {
		
		CasRestFormClient casClient = new CasRestFormClient();
		
		casClient.setConfiguration(configuration);
		casClient.setName(StringUtils.hasText(casProperties.getCasRestFormClientName()) ? casProperties.getCasRestFormClientName() : "RestFormClient");
		if(StringUtils.hasText(casProperties.getUsernameParameterName())) {	
			casClient.setUsernameParameter(casProperties.getUsernameParameterName());
		}
		if(StringUtils.hasText(casProperties.getPasswordParameterName())) {	
			casClient.setPasswordParameter(casProperties.getPasswordParameterName());
		}

		return casClient;
	}
	
}
