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
package org.apache.shiro.spring.boot.cas;

import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.StringUtils;
import org.jasig.cas.client.authentication.UrlPatternMatcherStrategy;

public class AntPatternMatcherStrategy implements UrlPatternMatcherStrategy {

	/**
	 * Any number of these characters are considered delimiters between multiple
	 * context config paths in a single String value.
	 */
	public static String CONFIG_LOCATION_DELIMITERS = ",; \t\n";
	private AntPathMatcher matcher = new AntPathMatcher();
	private String[] patterns;

	@Override
	public boolean matches(String url) {
		for (String pattern : patterns) {
			if (matcher.match(pattern, url)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void setPattern(String pattern) {
		this.patterns = StringUtils.tokenizeToStringArray(pattern, CONFIG_LOCATION_DELIMITERS);
	}


}

