package dev.vasileva.sample.jsonwebtoken.service;

import dev.vasileva.sample.jsonwebtoken.model.User;
import dev.vasileva.sample.jsonwebtoken.security.jwt.JwtAuthentication;
import dev.vasileva.sample.jsonwebtoken.security.jwt.JwtProvider;
import dev.vasileva.sample.jsonwebtoken.security.jwt.JwtRequest;
import dev.vasileva.sample.jsonwebtoken.security.jwt.JwtResponse;
import io.jsonwebtoken.Claims;
import jakarta.security.auth.message.AuthException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;
    /* Для хранения refresh токена мапа используется для упрощения примера. Лучше использовать постоянное хранилище,
    * например Redis */
    private final Map<String, String> refreshStorage = new HashMap<>();
    private final JwtProvider jwtProvider;

    public JwtResponse login(@NonNull JwtRequest authRequest) throws AuthException {
        /* Находим пользователя по логину */
        final User user = userService.getByLogin(authRequest.getLogin())
                .orElseThrow(() -> new AuthException("User is not found"));
        /* Проверяем, совпадает ли присланный пароль с паролем пользователя */
        if (user.getPassword().equals(authRequest.getPassword())) {
            /* Передаем объект пользователя в JwtProvider и получаем от него токены */
            final String accessToken = jwtProvider.generateAccessToken(user);
            final String refreshToken = jwtProvider.generateRefreshToken(user);
            /* Сохраняем выданный refresh токен в мапу refreshStorage*/
            refreshStorage.put(user.getLogin(), refreshToken);
            /* Возвращаем объект JwtResponse с токенами */
            return new JwtResponse(accessToken, refreshToken);
        } else {
            throw new AuthException("Incorrect Password");
        }
    }

    /* Этот метод принимает refresh токен и возвращает новый access токен */
    public JwtResponse getAccessToken(@NonNull String refreshToken) throws AuthException {
        /* Проверяем валидность присланного refresh токена */
        if (jwtProvider.validateRefreshToken(refreshToken)) {
            /* Из refresh токена получаем claims */
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            /* Из claims получаем логин пользователя */
            final String login = claims.getSubject();
            /* По логину находим выданный пользователю refresh токен в мапе refreshStorage */
            final String saveRefreshToken = refreshStorage.get(login);
            /* Сверяем refresh токен, найденный в хранилище, с присланным refresh токеном */
            if (saveRefreshToken != null && saveRefreshToken.equals(refreshToken)) {
                /* Находим пользователя по логину */
                final User user = userService.getByLogin(login).orElseThrow(() -> new AuthException("User is not found"));
                /* При помощи пользователя получаем новый access токен без обновления refresh токена */
                final String accessToken = jwtProvider.generateAccessToken(user);
                return new JwtResponse(accessToken, null);
            }
        }
        return new JwtResponse(null, null);
    }

    public JwtResponse refresh(@NonNull String refreshToken) throws AuthException {
        if (jwtProvider.validateRefreshToken(refreshToken)) {
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            final String login = claims.getSubject();
            final String saveRefreshToken = refreshStorage.get(login);
            if (saveRefreshToken != null && saveRefreshToken.equals(refreshToken)) {
                final User user = userService.getByLogin(login).orElseThrow(() -> new AuthException("User is not found"));
                final String accessToken = jwtProvider.generateAccessToken(user);
                final String newRefreshToken = jwtProvider.generateRefreshToken(user);
                refreshStorage.put(user.getLogin(), newRefreshToken);
                return new JwtResponse(accessToken, newRefreshToken);
            }
        }
        throw new AuthException("Invalid JWT token");
    }

    public JwtAuthentication getAuthInfo () {
        return (JwtAuthentication) SecurityContextHolder.getContext().getAuthentication();
    }

}
