package dev.vasileva.sample.jsonwebtoken.security.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;

// Объект-ответ, возвращаемый в ответе на запрос JwtRequest и содержащий access и refresh токены

@Getter
@AllArgsConstructor
public class JwtResponse {

    private final String type = "Bearer";
    private String accessToken;
    private String refreshToken;

}
