package com.example.jwt.refresh.study.jwt.user.factory;

import com.example.jwt.refresh.study.jwt.auth.provider.ProviderType;
import com.example.jwt.refresh.study.jwt.user.dto.info.KakaoOAuth2UserInfo;
import com.example.jwt.refresh.study.jwt.user.dto.info.OAuth2UserInfo;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(ProviderType providerType, Map<String, Object> attributes) {
        switch (providerType) {
            case KAKAO: return new KakaoOAuth2UserInfo(attributes);
            default: throw new IllegalArgumentException("Invalid Provider Type.");
        }
    }
}
