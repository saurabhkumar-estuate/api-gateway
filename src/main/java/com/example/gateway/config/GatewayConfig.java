package com.example.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

@Configuration
public class GatewayConfig {
	
	@Bean
    public KeyResolver userKeyResolver() {
        return exchange -> Mono.just(
                exchange.getRequest()
                        .getHeaders()
                        .getFirst(HttpHeaders.AUTHORIZATION) == null ? 
                        "anonymous" : exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION)
        );
    }

}
