package com.commons.security;

import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

@Configuration
public class DefaultSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("✅ DefaultSecurityConfig loaded in context");
        http.cors();
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeHttpRequests()
            .requestMatchers(
                "/.well-known/jwks.json",
                "/authuser/**",
                "/api/v1/register",
                "/api/v1/customer/register",
                "/api/v1/customers",
                "/api/v1/auth/login",
                "/api/v1/auth/m2mToken",
                "/api/v1/auth/openBankToken",
                "/oauth/token",
                "/api/v1/health"
            ).permitAll()
            .anyRequest().authenticated();

        http.oauth2ResourceServer()
            .bearerTokenResolver(bearerTokenResolver()) 
            .jwt()
            .jwtAuthenticationConverter(jwtAuthenticationConverter());

        http.formLogin().disable();
        http.httpBasic().disable();

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        System.out.println("✅ Custom JwtDecoder bean registered from DefaultSecurityConfig");

        return JwtDecoders.fromIssuerLocation("https://dev-wgk04dj5v68sbhre.us.auth0.com/");
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthorityPrefix("SCOPE_");
        converter.setAuthoritiesClaimName("scope");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
        return jwtConverter;
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("http://localhost:4200");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        return source;
    }
    
    
    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        resolver.setAllowUriQueryParameter(true); // Optional: if you want to allow ?access_token=
        return resolver;
    }

    @PostConstruct
    public void init() {
        System.out.println("🔒 Spring Security config initialized");
    }
    
    
   
}
