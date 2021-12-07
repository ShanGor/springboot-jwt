package cn.gzten.jwt.dto;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.GrantedAuthority;

import java.util.*;

/**
 * It is for the `claim` part for the JWT.
 */
public class JwtPayload {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private String username;

    private List<String> roles;

    public JwtPayload() {
        roles = new LinkedList<>();
    }

    public JwtPayload(String username) {
        this();
        this.setUsername(username);
    }

    public JwtPayload(String username, Collection<? extends GrantedAuthority> authorities) {
        this(username);

        authorities.forEach(aut -> {
            this.addRole(aut.getAuthority());
        });
    }

    public void addRole(String role) {
        this.roles.add(role);
    }

    public static final JwtPayload fromJson(final String json) throws JsonProcessingException {
        return objectMapper.readValue(json, JwtPayload.class);
    }

    public static final JwtPayload fromToken(final String token) {
        String payload = JWT.decode(token).getPayload();
        try {
            var o = objectMapper.readValue(new String(Base64.getDecoder().decode(payload)), LinkedHashMap.class);
            return fromJson((String) o.get("claimsInJson"));
        } catch (JsonProcessingException e) {
            throw new JWTDecodeException("Failed to process the payload!", e);
        }
    }

    @Override
    public String toString() {
        try {
            return objectMapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        roles.forEach(role -> this.roles.add(role));
    }
}
