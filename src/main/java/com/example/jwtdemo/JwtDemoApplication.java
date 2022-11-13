package com.example.jwtdemo;

import com.example.jwtdemo.domain.AppUser;
import com.example.jwtdemo.domain.Role;
import com.example.jwtdemo.service.AppUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@RequiredArgsConstructor
public class JwtDemoApplication {
    private final AppUserService appUserService;


    public static void main(String[] args) {
        SpringApplication.run(JwtDemoApplication.class, args);
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 存储时必须加密
     * @return
     */
    @Bean
    CommandLineRunner runner() {
        return args -> {
            appUserService.saveRole(new Role(null, "ROLE_USER"));
            appUserService.saveRole(new Role(null, "ROLE_MANAGE"));
            appUserService.saveRole(new Role(null, "ROLE_ADMIN"));
            appUserService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            appUserService.saveUser(new AppUser(null, "john smith", "john", "123456", new ArrayList<>()));
            appUserService.saveUser(new AppUser(null, "will smith", "will", "123456", new ArrayList<>()));
            appUserService.saveUser(new AppUser(null, "jim smith", "jim",
                    new BCryptPasswordEncoder().encode("123456"), new ArrayList<>()));
            appUserService.saveUser(new AppUser(null, "android smith", "android", "123456", new ArrayList<>()));

            appUserService.addRoleToAppUser("john","ROLE_USER");
            appUserService.addRoleToAppUser("will","ROLE_USER");
            appUserService.addRoleToAppUser("jim","ROLE_USER");
            appUserService.addRoleToAppUser("android","ROLE_USER");
            appUserService.addRoleToAppUser("android","ROLE_ADMIN");
        };
    }

}
