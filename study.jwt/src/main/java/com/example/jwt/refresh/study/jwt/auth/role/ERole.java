package com.example.jwt.refresh.study.jwt.auth.role;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;

@Getter
@AllArgsConstructor
public enum ERole {
    USER("ROLE_USER", "일반 사용자 권한"),
    ADMIN("ROLE_ADMIN", "관리자 권한"),
    GUEST("GUEST", "게스트 권한");


    private final String code;
    private final String displayName;

    public static ERole of(String code) {
        return Arrays.stream(ERole.values())
                .filter(r-> r.getCode().equals(code))
                .findAny()
                .orElse(GUEST);
    }
}
