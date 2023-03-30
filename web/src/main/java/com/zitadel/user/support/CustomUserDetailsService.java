package com.zitadel.user.support;

import com.zitadel.user.model.Users;
import com.zitadel.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * @Package demo.support
 * @ClassName CustomUserDetailsService
 * @Description TODO
 * @Author Ryan
 * @Date 3/23/2023
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users sysUser = this.userRepository.getByName(username).orElse(null);

        if (sysUser == null) {
            throw new UsernameNotFoundException("Not Found");
        }

        User.UserBuilder builder = User.builder()
                .username(sysUser.getName())
                .password("{noop}" + sysUser.getPassword()).passwordEncoder(x -> NoOpPasswordEncoder.getInstance().encode(x));

        Map<String, Object> params = new HashMap<>();
        params.put("user_id", sysUser.getId());


        builder.roles(sysUser.getRoles().split(","));

        return builder.build();
    }
}

