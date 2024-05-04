package com.SpringSecurity.project;

import com.SpringSecurity.project.controller.RegisterRequest;
import com.SpringSecurity.project.entity.Role;
import com.SpringSecurity.project.service.AuthenticationService;
import com.SpringSecurity.project.service.AuthenticationServiceImp;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.SpringSecurity.project.entity.Role.*;

@SpringBootApplication
public class ProjectApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProjectApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationServiceImp service
	){
		return args ->{
			var admin = RegisterRequest.builder()
					.firstName("Admin")
					.lastName("Admin")
					.email("Admin@mail.com")
					.password("12345")
					.role(ADMIN)
					.build();
			System.out.println("Admin token: " + service.register(admin).getToken());


			var manager = RegisterRequest.builder()
					.firstName("Manager")
					.lastName("Manager")
					.email("Manager@mail.com")
					.password("12345")
					.role(MANAGER)
					.build();
			System.out.println("manager token: " + service.register(manager).getToken());

		};
	}
}
