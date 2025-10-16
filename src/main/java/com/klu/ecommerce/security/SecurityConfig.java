package com.klu.ecommerce.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable() // adjust as needed
            .authorizeRequests(authorize -> authorize
                // allow public GET endpoints
                .antMatchers(HttpMethod.GET, "/products/**", "/public/**").permitAll()
                // allow login and static resources
                .antMatchers("/login", "/css/**", "/js/**", "/images/**").permitAll()
                // admin-only endpoints
                .antMatchers("/admin/**").hasRole("ADMIN")
                // any other request requires authentication
                .anyRequest().authenticated()
            )
            // default form login (customize as needed)
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}
