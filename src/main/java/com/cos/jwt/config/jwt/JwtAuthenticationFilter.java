package com.cos.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("jwtAuthFilter : 시도");
        // 아이디 비밀번호 받아서
        // 정상인지 로그인 시도
        // authenticationManager 로그인 시도 -> PrincipalDetailsService의 loadBy~가 실행
        // PrincipalDetails 를 세션에 담고 (권한 관리)
        // jwt 토큰 만들어 응답
        return super.attemptAuthentication(request, response);
    }
}
