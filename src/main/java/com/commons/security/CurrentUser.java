package com.commons.security;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;


import jakarta.servlet.http.HttpServletRequest;


@Component
public class CurrentUser {
public String requireCustomerId(HttpServletRequest request) {
// 1) Try JWT claim
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
if (auth != null ) {
String cid = claim((Jwt) auth.getPrincipal(), "customer_id");
//if (cid == null) cid = claim(jwt, "https://mockbank/customer_id");
if (cid != null && !cid.isBlank()) return cid;
}
// 2) Fallback header for local/dev or if Istio injects it
String cidHeader = request.getHeader("X-Customer-Id");
if (cidHeader != null && !cidHeader.isBlank()) return cidHeader;


throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Customer id not found in token or header");
}


private String claim(Jwt jwt, String name) {
Object v = jwt.getClaims().get(name);
return v == null ? null : String.valueOf(v);
}
}