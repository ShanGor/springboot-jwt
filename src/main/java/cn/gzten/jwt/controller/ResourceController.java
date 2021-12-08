package cn.gzten.jwt.controller;

import cn.gzten.jwt.exception.AppException;
import cn.gzten.jwt.repository.UserRepository;
import cn.gzten.jwt.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.function.Supplier;

import static cn.gzten.jwt.domain.Role.ROLE_ADMIN;

/**
 * Created by nydiarra on 06/05/17.
 * Refactored by Samuel Chan at 8th Dec 2021.
 */
@RestController
public class ResourceController {
    @Autowired
    UserRepository userRepo;

    @GetMapping(value ="/admin/users")
    public Iterable<User> getAdminUsers(){
        return userRepo.findAll();
    }

    @GetMapping(value ="/users/{id}")
    public Mono<User> getUser(@PathVariable("id") Long id){
        var ou = userRepo.findById(id);

        return checkAuthorityAndReturn(ou, () -> Mono.justOrEmpty(ou));
    }

    public static final  <R> Mono<R> checkAuthorityAndReturn(final Optional<User> ou, final Supplier<Mono<R>> function) {
        return ReactiveSecurityContextHolder.getContext().flatMap(sc -> {
            if (sc.getAuthentication().getAuthorities().contains(ROLE_ADMIN)) {
                return function.get();
            } else {
                if (!ou.isEmpty() && ou.get().getUsername().equals(sc.getAuthentication().getPrincipal())) {
                    return function.get();
                }

                /**
                 * If it is empty, you will want to prompt 403 because you don't want ppl to know this user id not exist.
                 */
                throw new AppException(403, "Not authorized to resource!");
            }
        });
    }
}
