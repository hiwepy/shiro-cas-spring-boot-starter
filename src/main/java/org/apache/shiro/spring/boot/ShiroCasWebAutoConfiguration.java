package org.apache.shiro.spring.boot;

import java.util.Map;

import org.apache.commons.collections.MapUtils;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.spring.boot.cas.CasSubjectFactory;
import org.apache.shiro.spring.web.config.AbstractShiroWebConfiguration;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.filter.authc.AuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebAutoConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnWebApplication
@ConditionalOnClass({AuthenticationFilter.class})
@ConditionalOnProperty(prefix = ShiroCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroBizProperties.class })
public class ShiroCasWebAutoConfiguration extends AbstractShiroWebConfiguration {
	
	@Autowired
	private ShiroBizProperties bizProperties;
	
	/**
	 * 责任链定义 ：定义Shiro的逻辑处理责任链
	 */
	@Bean
    @Override
	protected ShiroFilterChainDefinition shiroFilterChainDefinition() {
		DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
		Map<String /* pattert */, String /* Chain names */> pathDefinitions = bizProperties.getFilterChainDefinitionMap();
		if (MapUtils.isNotEmpty(pathDefinitions)) {
			chainDefinition.addPathDefinitions(pathDefinitions);
			return chainDefinition;
		}
		chainDefinition.addPathDefinition("/logout", "logout");
		chainDefinition.addPathDefinition("/**", "authc");
		return chainDefinition;
	}
	
	@Bean
	@Override
    protected SubjectFactory subjectFactory() {
        return new CasSubjectFactory();
    }
	
}
