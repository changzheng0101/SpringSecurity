package com.example.jwtdemo.repo;

import com.example.jwtdemo.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author weixiao
 * @date 2022/11/12 17:35
 */
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
