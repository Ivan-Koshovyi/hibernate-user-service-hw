package mate.academy.dao;

import java.util.List;
import java.util.Optional;
import mate.academy.model.User;

public interface UserDao {
    User add(User user);

    Optional<User> findByLogin(String login);

    List<User> getAll();
}
