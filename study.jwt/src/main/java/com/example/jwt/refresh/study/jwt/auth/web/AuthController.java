package com.example.jwt.refresh.study.jwt.auth.web;

import com.example.jwt.refresh.study.jwt.auth.dto.request.AccessTokenRefreshRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignInRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignUpRequestDto;
import com.example.jwt.refresh.study.jwt.auth.service.AuthService;
import com.example.jwt.refresh.study.jwt.boot.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> signIn(@RequestBody SignInRequestDto signInRequestDto) throws Exception {
        return ResponseEntity.ok(authService.signIn(signInRequestDto));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> signOut(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization) throws Exception {
        return new ResponseEntity<>(authService.signOut(authorization), HttpStatus.OK);
    }

    @PostMapping("/signup/common")
    public ResponseEntity<?> signUpCommon(@RequestBody SignUpRequestDto signUpRequestDto) throws Exception {
        return new ResponseEntity<>(authService.signUpCommon(signUpRequestDto), HttpStatus.CREATED);
    }

    @PostMapping("getusername")
    public ResponseEntity<?> getUserName(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization) throws Exception {
        return new ResponseEntity<>(authService.getUserName(authorization), HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/signup/admin")
    public ResponseEntity<?> signUpAdmin(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
                                         @RequestBody SignUpRequestDto signUpRequestDto) throws Exception {
        return new ResponseEntity<>(authService.signUpAdmin(signUpRequestDto), HttpStatus.CREATED);
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<?> accessTokenRefresh(@RequestBody AccessTokenRefreshRequestDto accessTokenRefreshRequestDto) {
        return new ResponseEntity<>(authService.accessTokenRefresh(accessTokenRefreshRequestDto), HttpStatus.OK);
    }
}
