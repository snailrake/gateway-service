package ru.intership.gatewayservice.config;

import lombok.Getter;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakConfig {

    @Value("${services.keycloak.url}")
    private String serverUrl;

    @Getter
    @Value("${services.keycloak.realm}")
    private String realm;

    @Value("${services.keycloak.client}")
    private String clientId;

    @Value("${services.keycloak.username}")
    private String username;

    @Value("${services.keycloak.password}")
    private String password;

    @Value("${services.keycloak.client-secret}")
    private String clientSecret;

    @Bean
    public Keycloak keycloak() {
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.PASSWORD)
                .username(username)
                .password(password)
                .build();
    }
}
