package cn.gzten.springboot.jwt.repository;

import cn.gzten.springboot.jwt.domain.RandomCity;
import org.springframework.data.repository.CrudRepository;

/**
 * Created by nydiarra on 10/05/17.
 */
public interface RandomCityRepository extends CrudRepository<RandomCity, Long> {
}
