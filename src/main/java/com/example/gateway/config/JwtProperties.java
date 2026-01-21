package com.example.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "security.jwt")
public class JwtProperties {
	
	private String secret;

    private long expiration = 86400000;

 
}
