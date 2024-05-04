package com.SpringSecurity.project.config;


import com.SpringSecurity.project.repository.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtServices jwtService;

    private final UserDetailsService userDetailsService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
     //   System.out.println("--------------------------------------  "+ request.getHeader() + "\n"+request.getServerPort() + "\n"+ request.getHeader("Authorization"));
        final  String authHeader = request.getHeader("Authorization");

        final String jwt;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            //System.out.println("the  not check no bearer  -------------------");
            filterChain.doFilter(request, response);
            return;
        }

        try {


          //System.out.println("the in try block  dude auth header  -------------------" + authHeader);
            jwt = authHeader.substring(7);
            System.out.println("the user jwt -------------------" + jwt);
            userEmail = jwtService.extractUserName(jwt);

            System.out.println("the user mail -------------------" + userEmail);


            if (userEmail != null && SecurityContextHolder
                    .getContext()
                    .getAuthentication() == null) {
                 UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
                System.out.println("the user details "+ userDetails.getUsername());

                var isTokenValid = tokenRepository.findByToken(jwt)
                        .map(t-> !t.isExpired() && !t.isRevoked())
                        .orElse(false);


                if (jwtService.isTokenVaild(jwt, userDetails) && isTokenValid) {
                    System.out.println("the vaild  token -------------------True");
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    log.info("the auth object {}", authToken.isAuthenticated());
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            filterChain.doFilter(request, response);
        }
        catch (Exception exception){
            handlerExceptionResolver.resolveException(request, response, null, exception);
        }


    }
}
