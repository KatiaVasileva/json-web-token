package dev.vasileva.sample.jsonwebtoken.service;

import dev.vasileva.sample.jsonwebtoken.model.Role;
import dev.vasileva.sample.jsonwebtoken.model.User;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final List<User> users;

    public UserService () {
        this.users = List.of(
                new User("Anton", "1234", "Anton", "Ivanov", Collections.singleton(Role.USER)),
                new User("Sergei", "12345", "Sergei", "Petrov", Collections.singleton(Role.ADMIN))
        );
    }

    // Метод, который возвращает пользователя по логину.

    public Optional<User> getByLogin(@NonNull String login) {
        return users.stream().filter(user -> login.equals(user.getLogin()))
                .findFirst();
    }



}
