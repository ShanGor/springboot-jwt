package cn.gzten.springboot.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;


@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.authorizeExchange()
                .pathMatchers("/admin")
                .hasAuthority("ROLE_ADMIN")
                .pathMatchers("/oauth/token", "/health", "/test", "/test/*")
                .permitAll()
                .anyExchange()
                .authenticated()
                .and()
                .formLogin()
                .and()
                .csrf()
                .disable()
                .build();
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

}
