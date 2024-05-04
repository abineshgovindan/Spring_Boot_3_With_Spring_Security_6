package com.SpringSecurity.project.service;

import com.SpringSecurity.project.config.JwtServices;
import com.SpringSecurity.project.controller.AuthenticationRequest;
import com.SpringSecurity.project.controller.AuthenticationResponse;
import com.SpringSecurity.project.controller.RegisterRequest;
import com.SpringSecurity.project.entity.Role;
import com.SpringSecurity.project.entity.Token;
import com.SpringSecurity.project.entity.TokenType;
import com.SpringSecurity.project.entity.User;
import com.SpringSecurity.project.repository.TokenRepository;
import com.SpringSecurity.project.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImp implements AuthenticationService {


    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtServices jwtServices;
    private final AuthenticationManager authenticationManager;


    @Override
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedUser = userRepository.save(user);
        var jwtToken = jwtServices.generateToken(user);
        var refreshToken = jwtServices.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);


        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllVaidTokensByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);

    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword())
        );
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtServices.generateToken(user);
        var refreshToken = jwtServices.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .build();


    }

    @Override
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        final String refreshToken;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            //System.out.println("the  not check no bearer  -------------------");
            return;
        }

        try {


            refreshToken = authHeader.substring(7);
            userEmail = jwtServices.extractUserName(refreshToken);


            if (userEmail != null) {
                var user = userRepository.findByEmail(userEmail).orElseThrow();

//                var isTokenValid = tokenRepository.findByToken(jwt)
//                        .map(t-> !t.isExpired() && !t.isRevoked())
//                        .orElse(false);

                if (jwtServices.isTokenVaild(refreshToken, user)) {
                    var accessToken = jwtServices.generateToken(user);
                    revokeAllUserTokens(user);
                    var authResponse = AuthenticationResponse.builder()
                            .token(accessToken)
                            .refreshToken(refreshToken)
                            .build();
                    saveUserToken(user, accessToken);
                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


    }

}
