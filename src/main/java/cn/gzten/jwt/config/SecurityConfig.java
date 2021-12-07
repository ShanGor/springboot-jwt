package cn.gzten.jwt.config;

import cn.gzten.jwt.dto.JwtPayload;
import cn.gzten.jwt.service.JwtService;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferWrapper;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {
    @Autowired
    JwtService jwtService;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        var accessDeniedHandler = new ServerAccessDeniedHandler() {
            @Override
            public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
                var resp = exchange.getResponse();
                resp.setRawStatusCode(403);

                var mono = ReactiveSecurityContextHolder.getContext().map(ctx -> {
                    var aut = ctx.getAuthentication();
                    if (aut.isAuthenticated()) {
                        return resp.bufferFactory().wrap("User is not authorized to this operation!".getBytes());
                    } else {
                        return resp.bufferFactory().wrap(aut.getDetails()
                                .toString().getBytes(StandardCharsets.UTF_8));
                    }

                });
                return resp.writeAndFlushWith(Mono.just(mono));
            }
        };

        return http.authorizeExchange()
                .pathMatchers("/oauth/token", "/health", "/test", "/test/*")
                .permitAll()
                .and()
                .addFilterAt(bearerAuthenticationFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler)
                .and()
                .authorizeExchange()
                .pathMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                .anyExchange()
                .authenticated()
                .and()
                .csrf()
                .disable()
                .build();
    }

    private AuthenticationWebFilter bearerAuthenticationFilter() {
        AuthenticationWebFilter bearerAuthenticationFilter = new AuthenticationWebFilter((ReactiveAuthenticationManager) authentication ->
                Mono.just(authentication)
        );

        bearerAuthenticationFilter.setServerAuthenticationConverter(new JwtAuthenticationConverter(jwtService));

        return bearerAuthenticationFilter;
    }

    /**
     * The delegate password encoder, default encryption implementation is bcrypt.
     * It supports to match below implementations:
     * - bcrypt	new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
     * - ldap	    new org.springframework.security.crypto.password.LdapShaPasswordEncoder();
     * - MD4	    new org.springframework.security.crypto.password.Md4PasswordEncoder();
     * - MD5	    new org.springframework.security.crypto.password.MessageDigestPasswordEncoder(“MD5”);
     * - noop	    new org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance();
     * - pbkdf2	new org.springframework.security.crypto.password.Pbkdf2PasswordEncoder();
     * - scrypt	new org.springframework.security.crypto.scrypt.SCryptPasswordEncoder();
     * - SHA-1	new org.springframework.security.crypto.password.MessageDigestPasswordEncoder(“SHA-1”);
     * - SHA-256	new org.springframework.security.crypto.password.MessageDigestPasswordEncoder(“SHA-256”);
     * - sha256	new org.springframework.security.crypto.password.StandardPasswordEncoder();
     * - argon2	new org.springframework.security.crypto.argon2.Argon2PasswordEncoder();
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    static class JwtAuthentication implements Authentication {
        private boolean authenticated = false;
        private String credentials;
        private String details;
        private String principal;
        private String name;
        List<GrantedAuthority> authorities = new LinkedList<>();

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        public void addAuthority(String role) {
            authorities.add(new SimpleGrantedAuthority(role));
        }

        @Override
        public Object getCredentials() {
            return credentials;
        }
        public void setCredentials(String credentials) {
            this.credentials = credentials;
        }

        @Override
        public Object getDetails() {
            return details;
        }

        public void setDetails(String details) {
            this.details = details;
        }

        @Override
        public Object getPrincipal() {
            return principal;
        }

        public void setPrincipal(String principal) {
            this.principal = principal;
        }

        @Override
        public boolean isAuthenticated() {
            return authenticated;
        }

        @Override
        public void setAuthenticated(boolean authenticated) throws IllegalArgumentException {
            this.authenticated = authenticated;
        }

        @Override
        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }

    private static final String BEARER = "Bearer ";

    static class JwtAuthenticationConverter implements ServerAuthenticationConverter {
        JwtAuthentication authentication;
        JwtService jwtService;
        public JwtAuthenticationConverter(JwtService jwtService) {
            authentication = new JwtAuthentication();
            this.jwtService = jwtService;
        }

        @Override
        public Mono<Authentication> convert(ServerWebExchange exchange) {
            var auths = exchange.getRequest().getHeaders().get("Authorization");
            if (auths == null || auths.isEmpty()) {
                authentication.setAuthenticated(false);
                authentication.setDetails("Please provide JWT as `Authorization` in HTTP Header!!");

            } else {
                String auth = auths.get(0);
                if (StringUtils.hasLength(auth) && auth.trim().length() > BEARER.length() && auth.trim().startsWith(BEARER)) {
                    String token = auth.trim().substring(BEARER.length());
                    try {
                        if (jwtService.isValid(token)) {
                            var payload = JwtPayload.fromToken(token);
                            authentication.setAuthenticated(true);
                            authentication.setName(payload.getUsername());
                            authentication.setPrincipal(payload.getUsername());
                            payload.getRoles().forEach(role -> authentication.addAuthority(role));
                        }
                    } catch (JWTVerificationException e) {
                        authentication.setAuthenticated(false);
                        authentication.setDetails("JWT failed to pass the verification: " + e.getMessage());
                    }
                }
            }

            return Mono.just(authentication);
        }
    }

}
