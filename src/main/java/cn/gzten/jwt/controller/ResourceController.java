package cn.gzten.jwt.controller;

import cn.gzten.jwt.service.GenericService;
import cn.gzten.jwt.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Created by nydiarra on 06/05/17.
 */
@RestController
@RequestMapping("/springjwt")
public class ResourceController {
    @Autowired
    GenericService userService;

    @RequestMapping(value ="/users", method = RequestMethod.GET)
    public List<User> getUsers(){
        return userService.findAllUsers();
    }
}
