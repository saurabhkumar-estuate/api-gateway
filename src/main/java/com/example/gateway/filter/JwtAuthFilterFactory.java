package com.example.gateway.filter;

import com.example.gateway.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilterFactory
        extends AbstractGatewayFilterFactory<JwtAuthFilterFactory.Config> {

    private static final Logger logger =
            LoggerFactory.getLogger(JwtAuthFilterFactory.class);

    private final JwtProperties jwtProperties;
    private final ReactiveStringRedisTemplate redisTemplate;

    public JwtAuthFilterFactory(
            JwtProperties jwtProperties,
            ReactiveStringRedisTemplate redisTemplate
    ) {
        super(Config.class);
        this.jwtProperties = jwtProperties;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            ServerHttpRequest request = exchange.getRequest();
            logger.info("JWT filter executing for path: {}", request.getPath());

            String authHeader =
                    request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            // 1️⃣ Missing Authorization header
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                logger.warn("Missing or invalid Authorization header");
                return onError(exchange,
                        "Missing or invalid Authorization header",
                        HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            // 2️⃣ Validate JWT signature
            if (!isValidToken(token)) {
                logger.warn("Invalid JWT token");
                return onError(exchange,
                        "Invalid or expired JWT token",
                        HttpStatus.UNAUTHORIZED);
            }

            // 3️⃣ Check Redis blacklist (logout support)
            return redisTemplate.hasKey(token)
                    .flatMap(isBlacklisted -> {

                        if (Boolean.TRUE.equals(isBlacklisted)) {
                            logger.warn("JWT token is blacklisted (logged out)");
                            return onError(exchange,
                                    "Token has been revoked",
                                    HttpStatus.UNAUTHORIZED);
                        }

                        logger.info("JWT token accepted");
                        return chain.filter(exchange);
                    });
        };
    }

    // JWT signature + expiry validation
    private boolean isValidToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(jwtProperties.getSecret().getBytes())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            logger.debug("Token valid for user: {}", claims.getSubject());
            return true;

        } catch (Exception ex) {
            logger.error("JWT validation failed: {}", ex.getMessage());
            return false;
        }
    }

    private Mono<Void> onError(
            ServerWebExchange exchange,
            String message,
            HttpStatus status
    ) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add("Content-Type", "application/json");

        String body = String.format(
                "{\"error\":\"%s\",\"status\":%d}",
                message,
                status.value()
        );

        return response.writeWith(
                Mono.just(response.bufferFactory().wrap(body.getBytes()))
        );
    }

    public static class Config {
        // future: roles, scopes, permissions
    }
}
