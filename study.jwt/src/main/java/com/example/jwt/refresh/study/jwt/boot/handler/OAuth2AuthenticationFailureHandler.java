package com.example.jwt.refresh.study.jwt.boot.handler;

import com.example.jwt.refresh.study.jwt.auth.domain.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.example.jwt.refresh.study.jwt.boot.util.CookieUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.naming.AuthenticationException;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    private final OAuth2AuthorizationRequestBasedOnCookieRepository auth2AuthorizationRequestBasedOnCookieRepository;

    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String targetUrl = CookieUtil.getCookie(req, "redirect_uri")
                .map(Cookie::getName)
                .orElse("/");

        exception.printStackTrace();

        targetUrl = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("error", exception.getLocalizedMessage())
                .build().toUriString();

        auth2AuthorizationRequestBasedOnCookieRepository.removeAuthorizationRequestCookies(req, response);

        getRedirectStrategy().sendRedirect(req, response, targetUrl);
    }
}
