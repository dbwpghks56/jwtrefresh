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
     * ?????????
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
             * RefreshToken??? ?????? ??? ????????? ??? ???, FakeRefreshToken??? ?????????????????????, ????????? DB??? ???????????? ??????
             * ??????, DB ?????? ?????? ???????????? ?????? ????????? ?????? ???????????? ????????????.
             */
            String fakeRefreshToken = passwordEncoder.encode(refreshToken);

            if(!authorities.contains("ROLE_ADMIN")) {
                Boolean isLogin = authTokenRepository.existsByUserSeq(userDetails.getSeq());
                if (isLogin) {
                    log.info("????????? ???????????? ?????? ??????????????????. DB?????? ????????? ??????????????????.");
                    authTokenRepository.deleteByUserSeq(userDetails.getSeq());
                }
            } else {
                log.info("???????????? ?????? ????????? ???????????? ????????????.");
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
        log.info("AccessToken??? ?????????????????????.");

        SecurityContextHolder.clearContext();

        return true;
    }

    @Transactional(readOnly = true)
    public String getUserName(String accessToken) throws Exception {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        return userDetails.getEmail() + userDetails.getSeq();
    }

    /**
     * ???????????? ( ?????? )
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
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "?????? Role??? ?????????????????????."));
        roles.add(trafficSafetyUserRole);
        newUserEntity.setRoles(roles);

        User userEntity = userRepository.save(newUserEntity);

        return true;
    }

    @Override
    @Transactional
    public Boolean signUpAdmin(SignUpRequestDto requestDto) throws Exception {
        if(userRepository.existsByUsername(requestDto.getUsername())){
            throw new RestException(HttpStatus.BAD_REQUEST, "?????? ???????????? ???????????????.");
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
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "???????????? Role ??? ?????? ???????????????. role=" + ERole.ADMIN));
        roles.add(adminRole);
        Role transUserRole = roleRepository.findByRole(ERole.USER)
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "???????????? Role ??? ?????? ???????????????. role=" + ERole.USER));
        roles.add(transUserRole);

        userEntity.setRoles(roles);
        userRepository.save(userEntity);

        return true;
    }

    /**
     * Refresh Token??? ???????????? ??? AccessToken??? ????????????.
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
            log.error("Refresh Token ??? ?????????????????????. ?????? ?????? ????????? DB?????? ???????????????.");
            authTokenRepository.deleteBySeq(accessTokenRefreshRequestDto.getRefreshToken());
            throw new RestException(HttpStatus.valueOf(401), "RefreshToken??? ?????????????????????. ?????? " +
                    "?????? ????????? DB?????? ???????????????.");
        }

        UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );
        String newAccessToken = jwtUtils.generateAccessToken(authenticationToken);

        AuthToken authTokenEntity = authTokenRepository.findBySeq(accessTokenRefreshRequestDto.getRefreshToken())
                .orElseThrow(() -> new RestException(HttpStatus.NOT_FOUND, "?????? ??? ??????"));

        authTokenEntity.updateAccessToken(newAccessToken);

        return AccessTokenRefreshResponseDto.builder()
                .accessToken(newAccessToken)
                .build();
    }
}






















