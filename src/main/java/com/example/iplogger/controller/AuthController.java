package com.example.iplogger.controller;

import com.example.iplogger.dto.LoginResponseDto;
import com.example.iplogger.entity.UserEntity;
import com.example.iplogger.security.TokenService;
import com.example.iplogger.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/user")
public class AuthController {
    private final UserService userService;
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthController(UserService userService, TokenService tokenService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public ResponseEntity registerUser(@RequestBody UserEntity data) {
        try {
            if (userService.findByUsername(data.getUsername()) != null) return ResponseEntity.badRequest().build();

            String encryptedPassword = new BCryptPasswordEncoder().encode(data.getPassword());
            UserEntity newUser = new UserEntity(data.getUsername(), encryptedPassword);
            userService.createUser(newUser);

            var token = tokenService.generateToken(newUser);

            return ResponseEntity.ok(new LoginResponseDto(token));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity loginUser(@RequestBody UserEntity data) {
        try {
            var usernamePassword = new UsernamePasswordAuthenticationToken(data.getUsername(), data.getPassword());
            var auth = authenticationManager.authenticate(usernamePassword);

            UserEntity user = userService.findByUsername(usernamePassword.getName());
            var token = tokenService.generateToken(user);

            return ResponseEntity.ok(new LoginResponseDto(token));
        } catch (AuthenticationException authenticationException) {
            return ResponseEntity.badRequest().body(authenticationException.getMessage());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
