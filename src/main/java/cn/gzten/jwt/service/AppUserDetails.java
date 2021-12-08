package cn.gzten.jwt.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class AppUserDetails extends User {
    private String id;
    public AppUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public AppUserDetails(String id, String username, String password, Collection<? extends GrantedAuthority> authorities) {
        this(username, password, authorities);
        this.setId(id);
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
