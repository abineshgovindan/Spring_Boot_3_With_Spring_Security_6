package com.SpringSecurity.project.service;

import com.SpringSecurity.project.controller.AuthenticationRequest;
import com.SpringSecurity.project.controller.RegisterRequest;
import com.SpringSecurity.project.entity.User;
import com.SpringSecurity.project.model.UserModel;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface AuthenticationService {
   
    Object register(RegisterRequest request);

    Object authenticate(AuthenticationRequest request);

    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
}
