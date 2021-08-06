package cn.gzten.springboot.jwt.service;

import cn.gzten.springboot.jwt.domain.RandomCity;
import cn.gzten.springboot.jwt.domain.User;

import java.util.List;

/**
 * Created by nydiarra on 06/05/17.
 */
public interface GenericService {
    User findByUsername(String username);

    List<User> findAllUsers();

    List<RandomCity> findAllRandomCities();
}
