package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    // id,pw 가 정상적으로 들어와서 로그인 -> 토큰을 만들어주고 그걸 응답으로 보내줌
    // 이후 요청부터 토큰이 넘어오면 내가 발행한 토큰인지만 확인 (RSA, HS256)
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        System.out.println("필터3");

        if (req.getMethod().equals("POST")) {
            System.out.println("post 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);
            if (headerAuth.equals("abcd")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter outPrintWriter = res.getWriter();
                outPrintWriter.println("인증안됨");
            }
        }
    }
}
