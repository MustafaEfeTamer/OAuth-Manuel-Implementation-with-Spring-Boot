package com.efelikk.oAuth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SpringConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(req -> req.anyRequest().permitAll())  // herkes url lere erişebilir
                .csrf(csrf -> csrf.disable())  // açık olursa kullanıcı gelen POST/PUT/DELETE gibi işlemleri sahte saldırılardan korur.
                .build();   // security filter chain nesnesi oluşturup spring security'e bırakıyoruz
    }
}