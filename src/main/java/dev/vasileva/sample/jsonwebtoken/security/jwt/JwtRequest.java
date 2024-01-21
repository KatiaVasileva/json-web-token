package dev.vasileva.sample.jsonwebtoken.security.jwt;

import lombok.Getter;
import lombok.Setter;

// Объект-запрос, направляемый пользователем для получения JWT токена

@Getter
@Setter
public class JwtRequest {

    private String login;
    private String password;

}
