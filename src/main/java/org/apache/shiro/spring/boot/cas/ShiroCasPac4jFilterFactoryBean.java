/**
 * <p>Coyright (R) 2014 正方软件股份有限公司。<p>
 */
package org.apache.shiro.spring.boot.cas;

import javax.servlet.Filter;

import io.buji.pac4j.filter.CallbackFilter;
import io.buji.pac4j.filter.LogoutFilter;
import io.buji.pac4j.filter.SecurityFilter;


/**
 * 
 * @className ： ShiroCasPac4jFilterFactoryBean
 * @description ： TODO(描述这个类的作用)
 * @author ： <a href="https://github.com/vindell">vindell</a>
 * @date ： 2018年1月23日 下午4:04:18
 * @version V1.0
 */
public class ShiroCasPac4jFilterFactoryBean extends ShiroCasFilterFactoryBean {

	@Override
	protected boolean supports(Filter filter) {
		return filter instanceof SecurityFilter || filter instanceof CallbackFilter || filter instanceof LogoutFilter
				|| super.supports(filter);
	}

}
