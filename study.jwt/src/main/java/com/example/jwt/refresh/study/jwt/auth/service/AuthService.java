package com.example.jwt.refresh.study.jwt.auth.service;

import com.example.jwt.refresh.study.jwt.auth.dto.request.SignInRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignUpRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.response.SignInResponseDto;

public interface AuthService {
    SignInResponseDto signIn(SignInRequestDto signInRequestDto) throws Exception;
    Boolean signOut(String accessToken) throws Exception;
    Boolean signUpCommon(SignUpRequestDto requestDto) throws Exception;
    Boolean SignUpAdmin(SignUpRequestDto requestDto) throws Exception;

}
