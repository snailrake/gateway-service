package ru.intership.gatewayservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;
import ru.intership.gatewayservice.security.AccountAuthenticationProvider;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AccountAuthenticationProvider provider;

    @Bean
    protected SecurityWebFilterChain configure(ServerHttpSecurity http) {
        return http.httpBasic(Customizer.withDefaults())
                .headers(headerSpec ->
                        headerSpec.contentSecurityPolicy(contentSecurityPolicySpec ->
                                contentSecurityPolicySpec.policyDirectives("upgrade-insecure-requests")))
                .cors(Customizer.withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(requests -> {
                    requests.pathMatchers("/openid-connect/**").permitAll();
                    requests.pathMatchers("/portal/**").authenticated();
                    requests.pathMatchers("/logist/**").authenticated();
                    requests.pathMatchers("/driver/**").authenticated();
                    requests.pathMatchers("/dwh/**").authenticated();
                })
                .oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                        .authenticationManagerResolver(context -> Mono.just(provider))
                ).build();
    }
}
