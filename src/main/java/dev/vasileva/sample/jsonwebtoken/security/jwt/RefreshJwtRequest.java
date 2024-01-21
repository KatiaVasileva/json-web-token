package dev.vasileva.sample.jsonwebtoken.security.jwt;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshJwtRequest {

    private String refreshToken;

}
