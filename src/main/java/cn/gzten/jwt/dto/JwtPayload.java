package cn.gzten.jwt.dto;

import cn.gzten.jwt.exception.AppException;
import cn.gzten.util.JsonUtil;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.util.*;

/**
 * It is for the `claim` part for the JWT.
 */
public class JwtPayload {
    @Getter
    @Setter
    private String username;

    @Getter
    @Setter
    private String id;

    @Getter
    private List<String> roles;

    public JwtPayload() {
        roles = new LinkedList<>();
    }

    public JwtPayload(String id, String username) {
        this();
        this.setId(id);
        this.setUsername(username);
    }

    public JwtPayload(String id, String username, Collection<? extends GrantedAuthority> authorities) {
        this(id, username);

        authorities.forEach(aut -> {
            this.addRole(aut.getAuthority());
        });
    }

    public void addRole(String role) {
        this.roles.add(role);
    }

    public static final JwtPayload fromJson(final String json) throws JsonProcessingException {
        return JsonUtil.getObjectMapper().readValue(json, JwtPayload.class);
    }

    public static final JwtPayload fromToken(final String token) {
        String payload = JWT.decode(token).getPayload();
        try {
            var o = JsonUtil.getObjectMapper().readValue(new String(Base64.getDecoder().decode(payload)), LinkedHashMap.class);
            return fromJson((String) o.get("claimsInJson"));
        } catch (JsonProcessingException e) {
            throw new JWTDecodeException("Failed to process the payload!", e);
        }
    }

    @Override
    public String toString() {
        try {
            return JsonUtil.toString(this);
        } catch (JsonProcessingException e) {
            throw new AppException(400, e.toString());
        }
    }

    public void setRoles(List<String> roles) {
        roles.forEach(role -> this.roles.add(role));
    }

}
