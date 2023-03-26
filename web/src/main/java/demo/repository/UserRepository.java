package demo.repository;

import demo.model.Users;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @Package demo.repository
 * @ClassName UserRepository
 * @Description TODO
 * @Author Ryan
 * @Date 3/22/2023
 */
@Repository
public interface UserRepository extends CrudRepository<Users, Long> {
    Optional<Users> getByName(String name);
}
