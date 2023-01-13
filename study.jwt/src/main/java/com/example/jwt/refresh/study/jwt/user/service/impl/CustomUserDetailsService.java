package com.example.jwt.refresh.study.jwt.user.service.impl;

import com.example.jwt.refresh.study.jwt.boot.exception.RestException;
import com.example.jwt.refresh.study.jwt.user.domain.model.User;
import com.example.jwt.refresh.study.jwt.user.domain.repository.UserRepository;
import com.example.jwt.refresh.study.jwt.user.dto.principal.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당 유저를 찾을 수 없습니다"));

        return UserPrincipal.create(userEntity);
    }
}
