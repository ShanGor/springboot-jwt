package cn.gzten.jwt.service;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class AppUserDetails extends User {
    @Getter @Setter
    private String id;
    public AppUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public AppUserDetails(String id, String username, String password, Collection<? extends GrantedAuthority> authorities) {
        this(username, password, authorities);
        this.setId(id);
    }
}
