package ru.intership.gatewayservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;
import ru.intership.gatewayservice.security.AccountAuthenticationProvider;
import ru.intership.gatewayservice.security.model.UserRole;

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
                    requests.pathMatchers("/portal/user/owner").permitAll();
                    requests.pathMatchers(HttpMethod.POST, "/portal/company").hasAnyAuthority(UserRole.REGISTRATOR.name());
                    requests.pathMatchers("/portal/user/member").hasAnyAuthority(UserRole.ADMIN.name());
                    requests.pathMatchers(HttpMethod.GET, "/portal/company/**").hasAnyAuthority(UserRole.ADMIN.name());
                    requests.pathMatchers(HttpMethod.GET, "/portal/user/company/**").hasAnyAuthority(UserRole.ADMIN.name());
                    requests.pathMatchers("/portal/user/**").authenticated();
                    requests.pathMatchers("/portal/role/**").authenticated();
                    requests.pathMatchers(HttpMethod.POST, "/portal/vehicle/**").hasAnyAuthority(UserRole.LOGIST.name(), UserRole.ADMIN.name());
                    requests.pathMatchers(HttpMethod.POST, "/portal/user/driver/**").hasAnyAuthority(UserRole.LOGIST.name());
                    requests.pathMatchers("/logist/**").authenticated();
                    requests.pathMatchers("/driver/**").authenticated();
                    requests.pathMatchers("/dwh/**").authenticated();
                })
                .oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                        .authenticationManagerResolver(context -> Mono.just(provider))
                ).build();
    }
}
