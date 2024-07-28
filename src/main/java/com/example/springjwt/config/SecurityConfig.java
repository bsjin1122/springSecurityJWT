package com.example.springjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	// 비밀번호 암호화
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		// csrf disable: 세션 방식에서는 세션이 고정이라 csrf 필수적으로 방어
		// JWT 방식: stateless 방식, csrf 공격 방어하지 않아도 됨
		http
			.csrf((auth)-> auth.disable());

		// form 로그인 방식 disable
		http
			.formLogin((auth) -> auth.disable());

		//http basic 인증 방식 disable
		http
			.httpBasic((auth) -> auth.disable());

		// 경로별 인가 작업
		http
			.authorizeHttpRequests((auth)-> auth
				.requestMatchers("/login", "/", "/join").permitAll()
				.requestMatchers("/admin").hasRole("ADMIN") //admin권한 가진 사용자들만
				.anyRequest().authenticated()); // 다른 요청들은 로그인한 사용자만 접근 가능하도록

		// 세션 설정
		http
			.sessionManagement((session)-> session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return http.build();
	}
}
