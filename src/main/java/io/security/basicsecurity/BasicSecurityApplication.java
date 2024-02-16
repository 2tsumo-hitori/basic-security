package io.security.basicsecurity;

import io.security.basicsecurity.controller.user.UserController;
import io.security.basicsecurity.domain.Account;
import io.security.basicsecurity.domain.AccountDto;
import io.security.basicsecurity.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BasicSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(BasicSecurityApplication.class, args);
	}

}
