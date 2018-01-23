package org.apache.shiro.spring.boot;

import org.pac4j.cas.config.CasProtocol;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(ShiroCasPac4jProperties.PREFIX)
public class ShiroCasPac4jProperties extends ShiroCasProperties{

	public static final String PREFIX = "shiro.cas";

	/** The Name of Client. */
	private String clientName;
	/** The protocol of the CAS Client. */
	private CasProtocol casProtocol = CasProtocol.CAS20_PROXY;
	
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
	
	

}
