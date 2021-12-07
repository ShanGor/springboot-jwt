package cn.gzten.jwt.dto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

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

    public static final JwtPayload fromJson(String json) throws JsonProcessingException {
        return objectMapper.readValue(json, JwtPayload.class);
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
