package ru.intership.gatewayservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang.SerializationException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.intership.gatewayservice.security.model.UserDetailsImpl;

@Component
@RequiredArgsConstructor
public class UserDataForwardFilter implements GlobalFilter {

    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .filter(context -> context.getAuthentication() != null)
                .flatMap(context -> {
                    UserDetailsImpl userDetails = (UserDetailsImpl) context.getAuthentication().getPrincipal();
                    ServerHttpRequest request = getModdedRequest(exchange, userDetails);
                    return chain.filter(exchange.mutate().request(request).build());
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    private ServerHttpRequest getModdedRequest(ServerWebExchange exchange, UserDetailsImpl user) {
        try {
            return exchange.getRequest().mutate()
                    .header("x-user-id", user.getUserId())
                    .header("x-user-name", user.getUsername())
                    .header("x-user-roles", objectMapper.writeValueAsString(user.getRoles()))
                    .build();
        } catch (JsonProcessingException e) {
            throw new SerializationException(e);
        }
    }
}
