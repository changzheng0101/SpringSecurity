package com.example.jwtdemo.service;

import com.example.jwtdemo.domain.AppUser;
import com.example.jwtdemo.domain.Role;

import java.util.List;

/**
 * @author weixiao
 * @date 2022/11/12 17:42
 */
public interface AppUserService {
    AppUser saveUser(AppUser user);

    Role saveRole(Role role);

    void addRoleToAppUser(String username, String roleName);

    AppUser getUser(String username);

    List<AppUser> getAllUser();
}
