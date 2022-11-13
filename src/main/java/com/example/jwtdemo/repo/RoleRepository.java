package com.example.jwtdemo.repo;

import com.example.jwtdemo.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author weixiao
 * @date 2022/11/12 17:36
 */
public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
