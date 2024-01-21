package dev.vasileva.sample.jsonwebtoken.security.jwt;

import dev.vasileva.sample.jsonwebtoken.model.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

// Генерирует и валидирует access и refresh токены.

@Slf4j
@Component
public class JwtProvider {

    private final SecretKey jwtAccessSecret;
    private final SecretKey jwtRefreshSecret;

    /* В конструктор передаем секретные ключи для подписи и валидации токенов. Один используется для генерации access токена,
    * а второй для генерации refresh токена. Это позволяет создать отдельные сервисы с бизнес логикой, которые не будут выдавать
    * токены, но зная ключ от access токена смогут их валидировать. При этом эти сервисы не будут знать ключ от refresh токена,
    * и если какой-то сервис будет скомпрометирован, то можно просто заменить ключ от access токена. */

    public JwtProvider(
            // С помощью @Value Spring подставляет значение из файла application.properties
            @Value("${jwt.secret.access}") String jwtAccessSecret,
            @Value("${jwt.secret.refresh}") String jwtRefreshSecret) {
        // Преобразуем Base64 обратно в массив байт и используем Keys.hmacShaKeyFor(), чтобы восстановить эиз этих байтов объект ключа SecretKey
        this.jwtAccessSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtAccessSecret));
        this.jwtRefreshSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtRefreshSecret));
    }

    /*Этот метод принимает объект пользователя и генерирует access токен для него.*/
    public String generateAccessToken(@NonNull User user) {
        /* Три строки ниже отвечают за определение времени жизни токена (5 минут) */
        final LocalDateTime now = LocalDateTime.now();
        final Instant accessExpirationInstant = now.plusMinutes(5).atZone(ZoneId.systemDefault()).toInstant();
        final Date accessExpiration = Date.from(accessExpirationInstant);
        /* Непосредственное создание access токена. Указываем логин пользователя, дату валидности токена, алгоритм шифрования,
        * произвольные claims: роли и имя пользователя*/
        return Jwts.builder()
                .subject(user.getLogin())
                .expiration(accessExpiration)
                .signWith(jwtAccessSecret)
                .claim("roles", user.getRoles())
                .claim("firstName", user.getFirstName())
                .compact();
    }

    /* Этот метод принимает объект пользователя и генерирует refresh токен для него. То же самое, что и для предыдущего метода,
    * но не передаем claims и указываем большее время жизни */
    public String generateRefreshToken(@NonNull User user) {
        final LocalDateTime now = LocalDateTime.now();
        final Instant refreshExirtionInstant = now.plusDays(30).atZone(ZoneId.systemDefault()).toInstant();
        final Date refreshExpiration = Date.from(refreshExirtionInstant);
        return Jwts.builder()
                .subject(user.getLogin())
                .expiration(refreshExpiration)
                .signWith(jwtRefreshSecret)
                .compact();
    }

    /* Этот метод отвечает за проверку валидности токена. Если токен протух или подписан неверно, то в лог запишется
    * соответствующее сообщение, а метод вернет false */
    public boolean validateAccessToken(@NonNull String accessToken) {
        return validateToken(accessToken, jwtAccessSecret);
    }

    public boolean validateRefreshToken (@NonNull String refreshToken) {
        return validateToken(refreshToken, jwtRefreshSecret);
    }

    private boolean validateToken(@NonNull String token, @NonNull SecretKey secret) {
        try {
            Jwts.parser()
                    .verifyWith(secret)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException expE) {
            log.error("Token expired", expE);
        } catch (UnsupportedJwtException unsE) {
            log.error("Unsupported JWT", unsE);
        } catch (MalformedJwtException mjE) {
            log.error("Malformed JWT", mjE);
        } catch (SignatureException sE) {
            log.error("Invalid Signature", sE);
        } catch (Exception e) {
            log.error("Invaid token", e);
        }
        return false;
    }

    public Claims getAccessClaims(@NonNull String token) {
        return getClaims(token, jwtAccessSecret);
    }

    public Claims getRefreshClaims(@NonNull String token) {
        return getClaims(token, jwtRefreshSecret);
    }

    private Claims getClaims(@NonNull String token, @NonNull SecretKey secret) {
        return Jwts.parser()
                .verifyWith(secret)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }



}
