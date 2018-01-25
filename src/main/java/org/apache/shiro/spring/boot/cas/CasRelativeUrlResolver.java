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
package org.apache.shiro.spring.boot.cas;

import org.apache.shiro.util.StringUtils;
import org.pac4j.core.context.ContextHelper;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.http.UrlResolver;

public class CasRelativeUrlResolver implements UrlResolver {

	private String contextPath;
	
	public CasRelativeUrlResolver(String contextPath) {
		this.contextPath = StringUtils.hasText(contextPath) ? contextPath : "/";
		if (this.contextPath.endsWith("/")) {
			this.contextPath = contextPath.substring(0, contextPath.length() - 1);
		}
	}
	
	@Override
    public String compute(final String url, WebContext context) {
        if (context != null && url != null && !url.startsWith("http://") && !url.startsWith("https://")) {
            final StringBuilder sb = new StringBuilder();

            sb.append(context.getScheme()).append("://").append(context.getServerName());

            final boolean notDefaultHttpPort = ContextHelper.isHttp(context) && context.getServerPort() != HttpConstants.DEFAULT_HTTP_PORT;
            final boolean notDefaultHttpsPort = ContextHelper.isHttps(context) && context.getServerPort() != HttpConstants.DEFAULT_HTTPS_PORT;
            if (notDefaultHttpPort || notDefaultHttpsPort) {
                sb.append(":").append(context.getServerPort());
            }

            sb.append(contextPath).append(url.startsWith("/") ? url : "/" + url);

            return sb.toString();
        }

        return url;
    }
}
