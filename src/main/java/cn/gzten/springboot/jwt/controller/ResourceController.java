package cn.gzten.springboot.jwt.controller;

import cn.gzten.springboot.jwt.service.GenericService;
import cn.gzten.springboot.jwt.domain.RandomCity;
import cn.gzten.springboot.jwt.domain.User;
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
    private GenericService userService;

    @RequestMapping(value ="/cities")
    public List<RandomCity> getUser(){
        return userService.findAllRandomCities();
    }

    @RequestMapping(value ="/users", method = RequestMethod.GET)
    public List<User> getUsers(){
        return userService.findAllUsers();
    }
}
