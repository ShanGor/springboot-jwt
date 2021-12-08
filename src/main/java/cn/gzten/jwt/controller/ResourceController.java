package cn.gzten.jwt.controller;

import cn.gzten.jwt.exception.AppException;
import cn.gzten.jwt.repository.UserRepository;
import cn.gzten.jwt.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
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

    /**
     * The performance would be better if you use String to pass the id.
     * When you are checking if a user has admin right to some specific object, you can:
     *  - add authority like 'admin:{object id}' to the user role. E.G. 'admin:1234'
     *  - Then it should hasAuthority('admin:' + #id)
     * @param id
     * @return
     */
    @PreAuthorize("hasAuthority('" + ROLE_ADMIN + "') || #id == principal")
    @GetMapping(value ="/users/{id}")
    public Mono<User> getUser(@PathVariable("id") String id){
        var ou = userRepo.findById(Long.parseLong(id));
        if (ou.isEmpty()) {
            throw new AppException(400, "Not found user by this id!");
        }
        return Mono.just(ou.get());

    }

    /**
     * For reference, maybe in the future need it.
     * @param ou
     * @param function
     * @param <R>
     * @return
     */
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
