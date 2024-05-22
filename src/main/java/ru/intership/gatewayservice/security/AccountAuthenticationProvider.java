package ru.intership.gatewayservice.security;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import reactor.core.publisher.Mono;
import ru.intership.gatewayservice.config.KeycloakConfig;
import ru.intership.gatewayservice.security.model.UserDetailsImpl;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class AccountAuthenticationProvider implements ReactiveAuthenticationManager {

    private static final String USER_ID_CLAIM = "sub";
    private final ReactiveJwtDecoder jwtDecoder;
    private final RealmResource realm;

    public AccountAuthenticationProvider(Keycloak keycloakClient, KeycloakConfig keycloakConfig, ReactiveJwtDecoder jwtDecoder) {
        this.realm = keycloakClient.realm(keycloakConfig.getRealm());
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        BearerTokenAuthenticationToken bearerTokenAuthentication = (BearerTokenAuthenticationToken) authentication;
        return getJwtToken(bearerTokenAuthentication).map(jwt -> {
                    String userId = jwt.getClaimAsString(USER_ID_CLAIM);
                    UserResource user = realm.users().get(userId);
                    return new UserDetailsImpl(userId, user.toRepresentation().getUsername(), rolesToAuthorities(user.roles().getAll().getClientMappings()));
                })
                .map(userDetails -> (Authentication) new UsernamePasswordAuthenticationToken(
                        userDetails,
                        bearerTokenAuthentication,
                        userDetails.getAuthorities())
                )
                .doOnError(throwable -> {
                    throw new HttpClientErrorException(HttpStatusCode.valueOf(401), throwable.getMessage());
                });
    }

    private Mono<Jwt> getJwtToken(BearerTokenAuthenticationToken bearer) {
        try {
            return this.jwtDecoder.decode(bearer.getToken());
        } catch (JwtException e) {
            throw new AuthenticationServiceException(e.getMessage(), e);
        }
    }

    private Collection<? extends GrantedAuthority> rolesToAuthorities(Map<String, ClientMappingsRepresentation> roles) {
        return roles.values().stream()
                .flatMap(clientMappings -> clientMappings.getMappings().stream())
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }
}
