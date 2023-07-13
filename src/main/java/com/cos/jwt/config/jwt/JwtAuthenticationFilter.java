package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.domain.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PipedReader;
import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("jwtAuthFilter : 시도");
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null)
//                System.out.println(input);
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            // 토크 넣어서 던지면
            // principalDetalisService의 loadUserByUsername()이 실행됨
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // authentication에 유저 정보가 당김
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authenticatioin 객체가 세션 영역에 저장됨 => 로그인에 저성공함
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUsername());
            System.out.println(principalDetails.getPassword());

            System.out.println("==========================");
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // 아이디 비밀번호 받아서
        // 정상인지 로그인 시도
        // authenticationManager 로그인 시도 -> PrincipalDetailsService의 loadBy~가 실행
        // PrincipalDetails 를 세션에 담고 (권한 관리)
        // jwt 토큰 만들어 응답
    }


    // 여기서 jwt 토큰 만들어서 응답
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("로그인 잘 됨");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String jwt = JWT.create()
                .withSubject("토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC256("cos"));
        response.addHeader("Authorization", "Bearer " + jwt);
    }
}
