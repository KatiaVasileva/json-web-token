package dev.vasileva.sample.jsonwebtoken.controller;

import dev.vasileva.sample.jsonwebtoken.security.jwt.JwtAuthentication;
import dev.vasileva.sample.jsonwebtoken.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// API c двумя эндпоинтами для вывода приветственного сообщения для пользователей с ролью USER и для пользователей
// с ролью ADMIN

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class Controller {

    private final AuthService authService;

    @PreAuthorize("hasAuthority('USER')")
    @GetMapping("/hello/user")
    public ResponseEntity<String> helloUser() {
        final JwtAuthentication authInfo = authService.getAuthInfo();
        return ResponseEntity.ok("Hello user " + authInfo.getPrincipal() + "!");
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/hello/admin")
    public ResponseEntity<String> helloAdmin() {
        final JwtAuthentication authInfo = authService.getAuthInfo();
        return ResponseEntity.ok("Hello admin " + authInfo.getPrincipal() + "!");
    }

}
