package com.example.jwt.refresh.study.jwt.user.service;

import com.example.jwt.refresh.study.jwt.auth.domain.model.Role;
import com.example.jwt.refresh.study.jwt.auth.provider.ProviderType;
import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import com.example.jwt.refresh.study.jwt.boot.exception.RestException;
import com.example.jwt.refresh.study.jwt.user.domain.model.User;
import com.example.jwt.refresh.study.jwt.user.domain.repository.UserRepository;
import com.example.jwt.refresh.study.jwt.user.dto.info.OAuth2UserInfo;
import com.example.jwt.refresh.study.jwt.user.dto.principal.UserPrincipal;
import com.example.jwt.refresh.study.jwt.user.factory.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User user = super.loadUser(userRequest);

        try {
            return this.process(userRequest, user);
        } catch(Exception ex) {
            ex.printStackTrace();
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User process(OAuth2UserRequest userRequest, OAuth2User user) {
        ProviderType providerType = ProviderType.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase());

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, user.getAttributes());
        User savedUser = userRepository.findByUsername(userInfo.getId()).get();

        if(savedUser != null) {
            if(providerType != savedUser.getProviderType()) {
                throw  new RestException(HttpStatus.BAD_REQUEST, "일단 오류");
            }

            updateUser(savedUser, userInfo);
        } else {
            savedUser = createUser(userInfo, providerType);
        }

        return UserPrincipal.create(savedUser, user.getAttributes());
    }

    private User createUser(OAuth2UserInfo userInfo, ProviderType providerType) {
        Set<Role> roles = new HashSet<>();
        roles.add(Role.builder().role(ERole.USER).build());
        LocalDateTime now = LocalDateTime.now();
        User user = User.builder()
                .username(userInfo.getId())
                .name(userInfo.getName())
                .email(userInfo.getEmail())
                .providerType(providerType)
                .roles(roles)
                .build();

        return userRepository.saveAndFlush(user);
    }

    private User updateUser(User user, OAuth2UserInfo userInfo) {
        if(userInfo.getName() != null && !user.getUsername().equals(userInfo.getId())) {
            user.setUsername(userInfo.getId());
        }

        return user;
    }
}





















