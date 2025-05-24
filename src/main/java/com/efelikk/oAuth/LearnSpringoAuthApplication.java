package com.efelikk.oAuth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity			// spring security i aktifleştiriyoruz
public class LearnSpringoAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(LearnSpringoAuthApplication.class, args);
	}

}

