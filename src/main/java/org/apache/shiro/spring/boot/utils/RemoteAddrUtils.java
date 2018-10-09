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
package org.apache.shiro.spring.boot.utils;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;

/**
 * http://blog.csdn.net/caoshuming_500/article/details/20952329
 */
public class RemoteAddrUtils {

	private static String[] headers = new String[]{"Cdn-Src-Ip", "X-Real-IP", "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR"};
	private static String localIP = "127.0.0.1";       
	
	/**
	 * 获取请求客户端IP地址，支持代理服务器
	 * @param request {@link HttpServletRequest} instance
	 * @return IP地址
	 */
	public static String getRemoteAddr(HttpServletRequest request) {
		
		// 1、获取客户端IP地址，支持代理服务器
		String remoteAddr = null;
		for (String header : headers) {
			remoteAddr = request.getHeader(header);
			if(!StringUtils.isEmpty(remoteAddr) && !StringUtils.equals(remoteAddr, "unknown")){
				break;
			}
		}
		// 2、没有取得特定标记的值
		if(StringUtils.isEmpty(remoteAddr) ){
			remoteAddr = request.getRemoteAddr();
		}
		
		// 3、判断是否localhost访问
		if(StringUtils.equals(remoteAddr, "localhost")){
			remoteAddr = localIP;
		}
		 
		return remoteAddr;
	}
}
