package com.example.jwt.refresh.study.jwt.auth.service.impl;

import com.example.jwt.refresh.study.jwt.auth.domain.model.AuthToken;
import com.example.jwt.refresh.study.jwt.auth.domain.model.Role;
import com.example.jwt.refresh.study.jwt.auth.domain.repository.AuthTokenRepository;
import com.example.jwt.refresh.study.jwt.auth.domain.repository.RoleRepository;
import com.example.jwt.refresh.study.jwt.auth.dto.request.AccessTokenRefreshRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignInRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignUpRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.response.AccessTokenRefreshResponseDto;
import com.example.jwt.refresh.study.jwt.auth.dto.response.SignInResponseDto;
import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import com.example.jwt.refresh.study.jwt.auth.service.AuthService;
import com.example.jwt.refresh.study.jwt.boot.exception.RestException;
import com.example.jwt.refresh.study.jwt.boot.util.JwtUtils;
import com.example.jwt.refresh.study.jwt.user.domain.model.User;
import com.example.jwt.refresh.study.jwt.user.domain.repository.UserRepository;
import com.example.jwt.refresh.study.jwt.user.service.impl.UserDetailsImpl;
import com.example.jwt.refresh.study.jwt.user.service.impl.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final AuthTokenRepository authTokenRepository;

    private final UserDetailsServiceImpl userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;

    /*
     * 로그인
     * @param signInRequestDto
     * @return
     * @throws Exception
     */
    @Override
    @Transactional
    public SignInResponseDto signIn(SignInRequestDto signInRequestDto) throws Exception {
        try {
            Authentication authentication = null;
            Boolean isNewUser = false;

            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    signInRequestDto.getUsername(),
                    signInRequestDto.getPassword()
            ));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtUtils.generateAccessToken(authentication);
            String refreshToken = jwtUtils.generateRefreshToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            Set<String> authorities = userDetails.getAuthorities().stream()
                    .map(role -> role.getAuthority())
                    .collect(Collectors.toSet());

            /**
             * RefreshToken을 한번 더 암호화 한 후, FakeRefreshToken을 사용자응답으로, 그리고 DB에 인덱스로 저장
             * 만일, DB 내에 해당 사용자가 이미 존재할 경우 기존값을 대체한다.
             */
            String fakeRefreshToken = passwordEncoder.encode(refreshToken);

            if(!authorities.contains("ROLE_ADMIN")) {
                Boolean isLogin = authTokenRepository.existsByUserSeq(userDetails.getSeq());
                if (isLogin) {
                    log.info("기본에 로그인된 일반 사용자입니다. DB값을 제거후 재삽입합니다.");
                    authTokenRepository.deleteByUserSeq(userDetails.getSeq());
                }
            } else {
                log.info("관리자는 중복 로그인 체크하지 않습니다.");
            }

            AuthToken authTokenEntity = AuthToken.builder()
                    .seq(fakeRefreshToken)
                    .userSeq(userDetails.getSeq())
                    .refreshToken(refreshToken)
                    .accessToken(accessToken)
                    .build();

            authTokenRepository.save(authTokenEntity);

            SignInResponseDto signInResponseDto = SignInResponseDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userSeq(userDetails.getSeq())
                    .username(userDetails.getUsername())
                    .type("Bearer")
                    .roles(authorities)
                    .build();

            return signInResponseDto;
        } catch (Exception e) {

            e.printStackTrace();
            log.info(e.getClass().getSimpleName());
            log.info(e.getMessage());
        }
        return null;
    }

    @Override
    @Transactional
    public Boolean signOut(String accessToken) throws Exception {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        accessToken = accessToken.replace("Bearer ", "");
        Integer deletedCnt = authTokenRepository.deleteByAccessToken(accessToken);
        log.info("AccessToken이 제거되었습니다.");

        SecurityContextHolder.clearContext();

        return true;
    }

    @Transactional(readOnly = true)
    public String getUserName(String accessToken) throws Exception {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        return userDetails.getEmail() + userDetails.getSeq();
    }

    /**
     * 회원가입 ( 유저 )
     * @param requestDto
     * @throws Exception
     *
     */
    @Override
    @Transactional
    public Boolean signUpCommon(SignUpRequestDto requestDto) throws Exception {
        User newUserEntity = null;
        Set<Role> roles = new HashSet<>();

        newUserEntity = User.builder()
                .username(requestDto.getUsername())
                .password(passwordEncoder.encode(requestDto.getPassword()))
                .name(requestDto.getName())
                .birth(requestDto.getBirth())
                .gender(requestDto.getGender())
                .email(requestDto.getEmail())
                .pushToken(requestDto.getPushToken())
                .build();

        Role trafficSafetyUserRole = roleRepository.findByRole(ERole.USER)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당 Role을 찾지못했습니다."));
        roles.add(trafficSafetyUserRole);
        newUserEntity.setRoles(roles);

        User userEntity = userRepository.save(newUserEntity);

        return true;
    }

    @Override
    @Transactional
    public Boolean signUpAdmin(SignUpRequestDto requestDto) throws Exception {
        if(userRepository.existsByUsername(requestDto.getUsername())){
            throw new RestException(HttpStatus.BAD_REQUEST, "이미 존재하는 계정입니다.");
        }

        User userEntity = User.builder()
                .username(requestDto.getUsername())
                .password(passwordEncoder.encode(requestDto.getPassword()))
                .name(requestDto.getName())
                .birth(requestDto.getBirth())
                .gender(requestDto.getGender())
                .email(requestDto.getEmail())
                .pushToken(requestDto.getPushToken())
                .build();

        Set<Role> roles = new HashSet<>();

        Role adminRole = roleRepository.findByRole(ERole.ADMIN)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당하는 Role 을 찾지 못했습니다. role=" + ERole.ADMIN));
        roles.add(adminRole);
        Role transUserRole = roleRepository.findByRole(ERole.USER)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "해당하는 Role 을 찾지 못했습니다. role=" + ERole.USER));
        roles.add(transUserRole);

        userEntity.setRoles(roles);
        userRepository.save(userEntity);

        return true;
    }

    /**
     * Refresh Token을 검사하여 새 AccessToken을 반환한다.
     * @param accessTokenRefreshRequestDto
     * @return
     */
    @Override
    @Transactional(noRollbackFor = RestException.class)
    public AccessTokenRefreshResponseDto accessTokenRefresh(AccessTokenRefreshRequestDto accessTokenRefreshRequestDto) {
        accessTokenRefreshRequestDto.setAccessToken(jwtUtils.getAccessTokenFromBearer(
                accessTokenRefreshRequestDto.getAccessToken()
        ));
        String username = jwtUtils.getUserNameFromAccessToken(accessTokenRefreshRequestDto.getAccessToken());

        if(!userRepository.existsByUsername(username)) {
            throw new UsernameNotFoundException(username);
        }

        if(!authTokenRepository.existsByAccessTokenAndSeq(accessTokenRefreshRequestDto.getAccessToken(),
                accessTokenRefreshRequestDto.getRefreshToken())) {
            log.error("Refresh Token 이 만료되었습니다. 해당 토근 정보를 DB에서 제거합니다.");
            authTokenRepository.deleteBySeq(accessTokenRefreshRequestDto.getRefreshToken());
            throw new RestException(HttpStatus.valueOf(401), "RefreshToken이 만료되었습니다. 해당 " +
                    "토큰 정보를 DB에서 제거합니다.");
        }

        UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );
        String newAccessToken = jwtUtils.generateAccessToken(authenticationToken);

        AuthToken authTokenEntity = authTokenRepository.findBySeq(accessTokenRefreshRequestDto.getRefreshToken())
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "찾을 수 없어"));

        authTokenEntity.updateAccessToken(newAccessToken);

        return AccessTokenRefreshResponseDto.builder()
                .accessToken(newAccessToken)
                .build();
    }
}






















