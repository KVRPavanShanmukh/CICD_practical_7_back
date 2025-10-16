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
            .csrf().disable() // keep or change depending on your needs
            .authorizeRequests(authorize -> authorize
                // public GET endpoints
                .antMatchers(HttpMethod.GET, "/products/**", "/api/public/**").permitAll()
                // allow static resources and login page
                .antMatchers("/login", "/css/**", "/js/**", "/images/**").permitAll()
                // admin endpoints require ADMIN role
                .antMatchers("/admin/**").hasRole("ADMIN")
                // all other requests require authentication
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}
