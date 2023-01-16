package com.example.jwt.refresh.study.jwt.boot.handler;

import com.example.jwt.refresh.study.jwt.auth.domain.model.AuthToken;
import com.example.jwt.refresh.study.jwt.auth.domain.model.Role;
import com.example.jwt.refresh.study.jwt.auth.domain.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.example.jwt.refresh.study.jwt.auth.factory.OAuth2UserInfoFactory;
import com.example.jwt.refresh.study.jwt.auth.provider.ProviderType;
import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import com.example.jwt.refresh.study.jwt.boot.properties.AppProperties;
import com.example.jwt.refresh.study.jwt.boot.util.CookieUtil;
import com.example.jwt.refresh.study.jwt.boot.util.JwtUtils;
import com.example.jwt.refresh.study.jwt.user.dto.info.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtUtils jwtUtils;
    private final AppProperties appProperties;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestBasedOnCookieRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if(response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect");
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected  String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtil.getCookie(request, "redirect_uri")
                .map(Cookie::getValue);

        if(redirectUri.isPresent() && !isAuthorizedRedirectUri((redirectUri.get()))) {
            throw new IllegalArgumentException("Sorry");
        }

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        ProviderType providerType = ProviderType.valueOf(authToken.getAuthorizedClientRegistrationId().toUpperCase());

        OidcUser user = ((OidcUser) authentication.getPrincipal());
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, user.getAttributes());
        Collection<? extends GrantedAuthority> authorities = ((OidcUser) authentication.getPrincipal()).getAuthorities();

        ERole roleType = hasAuthority(authorities, ERole.ADMIN.getCode()) ? ERole.ADMIN : ERole.USER;

        Date now = new Date();
        String accessToken = jwtUtils.generateAccessToken(authentication);

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("token", accessToken)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        authorizationRequestBasedOnCookieRepository.removeAuthorizationRequestCookies(request, response);
    }

    private boolean hasAuthority(Collection<? extends GrantedAuthority> authorities,String authority) {
        if(authorities == null) {
            return false;
        }
        for(GrantedAuthority grantedAuthority : authorities) {
            if(authority.equals(grantedAuthority.getAuthority())) {
                return true;
            }
        }

        return false;
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return appProperties.getOauth2().getAuthorizedRedirectUris()
                .stream()
                .anyMatch(s -> {
                    URI authorizedURI = URI.create(s);
                    if(authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost()) && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }

                    return false;
                });
    }
}
