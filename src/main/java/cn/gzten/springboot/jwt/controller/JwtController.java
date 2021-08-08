package cn.gzten.springboot.jwt.controller;

import cn.gzten.springboot.jwt.dto.JwtDto;
import cn.gzten.springboot.jwt.util.JwtUtils;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Locale;

@RestController
public class JwtController {
    private static final Logger log = LoggerFactory.getLogger(JwtController.class);
    private ReactiveUserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;

    @Value("${jwt.public-key-base64}")
    private String publicKeyBase64;
    @Value("${jwt.keystore.base64}")
    private String privateKeystoreBase64;
    @Value("${jwt.keystore.passcode}")
    private String keystorePass;
    @Value("${jwt.keystore.alias}")
    private String keyAlias;

    private JwtUtils jwtUtils;
    private static final List<String> EMPTY_HEADER = List.of("");

    @PostConstruct
    public void initJwtUtils() {
        this.jwtUtils = new JwtUtils(privateKeystoreBase64,
                keystorePass,
                keyAlias,
                publicKeyBase64);
    }

    public static record JwtRequest(@JsonProperty("grant_type") String grantType,
                                    @JsonProperty("username") String username,
                                    @JsonProperty("password") String password){};

    @PostMapping(value = "/oauth/token", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public Mono<JwtDto> generateJwt(ServerWebExchange exchange) {
        return getJwtRequest(exchange).flatMap(jwtRequest -> {
            if (jwtRequest.grantType == null || !jwtRequest.grantType.toLowerCase(Locale.ROOT).equals("password")) {
                return Mono.error(new JWTCreationException("Unknown grant_type provided: " + jwtRequest.grantType, new Exception()));
            }

            log.info("Request token: {}", jwtRequest.username);
            return userDetailsService.findByUsername(jwtRequest.username)
                    .map(userDetails -> {
                        if (passwordEncoder.matches(jwtRequest.password, userDetails.getPassword())) {
                            log.info("Got token for: {}", jwtRequest.username);
                            return jwtUtils.encrypt(jwtRequest.username);
                        } else {
                            log.info("Password incorrect for: {}", jwtRequest.username);
                            throw new UsernameNotFoundException("User not found or password incorrect!");
                        }
                    });
        });
    }

    @Autowired
    public void setUserDetailsService(ReactiveUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @GetMapping("/health")
    public String health() {
        return "";
    }

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    private static final Mono<JwtRequest> getJwtRequest(ServerWebExchange exchange) {
        return exchange.getFormData().map(m -> {
            var grantType = m.getOrDefault("grant_type", EMPTY_HEADER).get(0);
            var username = m.getOrDefault("username", EMPTY_HEADER).get(0);
            var password = m.getOrDefault("password", EMPTY_HEADER).get(0);
            return new JwtRequest(grantType, username, password);
        });
    }
}
