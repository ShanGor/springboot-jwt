package cn.gzten.jwt.config;

import cn.gzten.jwt.dto.JwtPayload;
import cn.gzten.jwt.service.JwtService;
import com.auth0.jwt.exceptions.JWTVerificationException;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
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

import static cn.gzten.jwt.domain.Role.ROLE_ADMIN;

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
                .pathMatchers("/admin/**").hasAuthority(ROLE_ADMIN)
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

    public static class JwtAuthentication implements Authentication {
        @Setter @Getter
        private boolean authenticated = false;
        @Getter @Setter
        private String credentials;
        @Setter
        private String details;
        @Setter @Getter
        private String principal;
        @Setter @Getter
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
        public Object getDetails() {
            return details;
        }
    }

    private static final String BEARER = "Bearer ";

    private static class JwtAuthenticationConverter implements ServerAuthenticationConverter {
        JwtService jwtService;
        public JwtAuthenticationConverter(JwtService jwtService) {
            this.jwtService = jwtService;
        }

        @Override
        public Mono<Authentication> convert(ServerWebExchange exchange) {
            JwtAuthentication authentication = new JwtAuthentication();
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
                            authentication.setPrincipal(payload.getId());
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
