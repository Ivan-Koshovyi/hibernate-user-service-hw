package mate.academy.service.impl;

import java.util.List;
import java.util.Optional;
import mate.academy.dao.UserDao;
import mate.academy.lib.Inject;
import mate.academy.lib.Service;
import mate.academy.model.User;
import mate.academy.service.UserService;
import mate.academy.util.HashUtil;

@Service
public class UserServiceImpl implements UserService {

    @Inject
    private UserDao userDao;

    @Override
    public User add(User user) {
        user.setSalt(HashUtil.getSalt());
        user.setPassword(HashUtil.hashPassword(user.getPassword(), user.getSalt()));
        return userDao.add(user);
    }

    @Override
    public Optional<User> findByLogin(String login) {
        return userDao.findByLogin(login);
    }

    @Override
    public List<User> getAll() {
        return userDao.getAll();
    }
}
