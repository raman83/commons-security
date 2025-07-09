package com.commons.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.annotation.PostConstruct;

@Configuration
public class DefaultSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    	
    	System.out.print("Loadedddddddddddddddddd!!!!!!!!!!!!!!!!!!!!!");
        http
            .csrf().disable() // Important: disable CSRF for non-browser POSTs

            .authorizeHttpRequests()
            .requestMatchers("/.well-known/jwks.json","/api/v1/register","/api/v1/customer/register","/api/v1/customers","/api/v1/auth/login",
                    "/oauth/token").permitAll()
            .requestMatchers("/health").permitAll() // Optional health check
                .anyRequest().authenticated()
            .and()
            .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter());

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("SCOPE_");
        authoritiesConverter.setAuthoritiesClaimName("scope");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return jwtConverter;
    }
    
    
    @PostConstruct
    public void init() {
        System.out.println("✅ DefaultSecurityConfig loaded in context");
    }
}
