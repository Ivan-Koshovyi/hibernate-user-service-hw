package mate.academy.security;

import java.util.Optional;
import mate.academy.exception.AuthenticationException;
import mate.academy.exception.RegistrationException;
import mate.academy.lib.Inject;
import mate.academy.lib.Service;
import mate.academy.model.User;
import mate.academy.service.UserService;
import mate.academy.util.HashUtil;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    @Inject
    private UserService userService;

    @Override
    public void register(String login, String password) throws RegistrationException {
        try {
            User user = new User();
            user.setLogin(login);
            user.setPassword(password);
            userService.add(user);
        } catch (Exception e) {
            throw new RegistrationException("Can't register user with login: " + login);
        }
    }

    @Override
    public User login(String login, String password) throws AuthenticationException {
        Optional<User> userFromDbOptional = userService.findByLogin(login);
        if (userFromDbOptional.isEmpty()) {
            throw new AuthenticationException("Can't find user from DB");
        }
        User user = userFromDbOptional.get();
        String hashedPassword = HashUtil.hashPassword(password, user.getSalt());
        if (user.getPassword().equals(hashedPassword)) {
            return user;
        }
        throw new ArithmeticException("Incorrect password");
    }
}
