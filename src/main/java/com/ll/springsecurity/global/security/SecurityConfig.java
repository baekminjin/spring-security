package com.ll.springsecurity.global.security;

import com.ll.springsecurity.global.rsData.RsData;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.ll.springsecurity.standard.util.Ut;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
	private final CustomAuthenticationFilter customAuthenticationFilter;

	@Bean
	public SecurityFilterChain baseSecurityFilterChain(HttpSecurity http) throws Exception {
		http
				.authorizeHttpRequests(authorizeRequests ->
						authorizeRequests
								.requestMatchers("/h2-console/**")
								.permitAll()
								.requestMatchers(HttpMethod.GET, "/api/*/posts/{id:\\d+}", "/api/*/posts", "/api/*/posts/{postId:\\d+}/comments")
								.permitAll()
								.requestMatchers("/api/*/members/login", "/api/*/members/join")
								.permitAll()
								.anyRequest()
								.authenticated()
				)
				.headers(
						headers ->
								headers.frameOptions(
										frameOptions ->
												frameOptions.sameOrigin()
								)
				)
				.csrf(
						csrf ->
								csrf.disable()
				)

				.addFilterBefore(customAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.exceptionHandling(
						exceptionHandling -> exceptionHandling
								.authenticationEntryPoint(
										(request, response, authException) -> {
											response.setContentType("application/json;charset=UTF-8");
											response.setStatus(403);
											response.getWriter().write(
													Ut.json.toString(
															new RsData("403-1", request.getRequestURI() + ", " + authException.getLocalizedMessage())
													)
											);
										}
								)
				);

		return http.build();
	}
}