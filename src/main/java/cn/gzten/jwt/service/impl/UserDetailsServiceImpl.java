package cn.gzten.jwt.service.impl;

import cn.gzten.jwt.repository.UserRepository;
import cn.gzten.jwt.domain.User;
import cn.gzten.jwt.service.AppUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by nydiarra on 06/05/17.
 */
@Service
public class UserDetailsServiceImpl implements ReactiveUserDetailsService {
    private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    private UserRepository userRepository;

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        User user = userRepository.findByUsername(username);

        if(user == null) {
            throw new UsernameNotFoundException(String.format("The username %s doesn't exist", username));
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
        });

        return Mono.just(new AppUserDetails(String.valueOf(user.getId()), user.getUsername(), user.getPassword(), authorities));
    }


    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
}

