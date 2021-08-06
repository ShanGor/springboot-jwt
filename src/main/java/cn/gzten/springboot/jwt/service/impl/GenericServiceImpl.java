package cn.gzten.springboot.jwt.service.impl;

import cn.gzten.springboot.jwt.domain.RandomCity;
import cn.gzten.springboot.jwt.domain.User;
import cn.gzten.springboot.jwt.repository.RandomCityRepository;
import cn.gzten.springboot.jwt.repository.UserRepository;
import cn.gzten.springboot.jwt.service.GenericService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Created by nydiarra on 07/05/17.
 */
@Service
public class GenericServiceImpl implements GenericService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RandomCityRepository randomCityRepository;

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> findAllUsers() {
        return (List<User>)userRepository.findAll();
    }

    @Override
    public List<RandomCity> findAllRandomCities() {
        return (List<RandomCity>)randomCityRepository.findAll();
    }
}
