package cn.gzten.jwt.controller;

import cn.gzten.jwt.exception.AppException;
import cn.gzten.jwt.repository.UserRepository;
import cn.gzten.jwt.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

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

    @PreAuthorize("hasAuthority('" + ROLE_ADMIN + "') || #id == principal")
    @GetMapping(value ="/users/{id}")
    public Mono<User> getUser(@PathVariable("id") String id){
        var ou = userRepo.findById(Long.parseLong(id));
        if (ou.isEmpty()) {
            throw new AppException(400, "Not found user by this id!");
        }
        return Mono.just(ou.get());

    }
}
