package com.eazybytes.filter;

import com.eazybytes.utils.EmailValidator;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class RequestValidationBeforeFilter implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;
        String header = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null) {
            header = header.trim();
            if (StringUtils.startsWithIgnoreCase(header, "Basic ")) {
                byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
                byte[] decoded;
                try {
                    decoded = java.util.Base64.getDecoder().decode(base64Token);
                    String token = new String(decoded, StandardCharsets.UTF_8); //username:password
                    String[] values = token.split(":");
                    if (values.length == 2) {
                        String username = values[0];
                        String password = values[1];
                        if (EmailValidator.isEmailValido(username) && password.length() >= 8) {
                            filterChain.doFilter(servletRequest, servletResponse);
                        } else {
                            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                            throw new BadCredentialsException("Invalid username or password");
                        }
                    } else {
                        res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                        throw new BadCredentialsException("Missing username or password");
                    }
                } catch (IllegalArgumentException ex) {
                    res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    throw new BadCredentialsException("Invalid basic authentication token");
                }
            }
        }
    }
}
