package com.zitadel.user.config;

import com.zitadel.user.model.Users;
import com.zitadel.user.repository.UserRepository;
import com.zitadel.user.support.AccessTokenInterceptor;
import com.zitadel.user.support.TokenAccessor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

@Slf4j
@Configuration
@RequiredArgsConstructor
class WebClientConfig {
    private final TokenAccessor tokenAccessor;

    @Value("${zitadel.service.token}")
    private String serviceToken;

    @Bean
    @Qualifier("zitadel")
    RestTemplate restTemplate() {
        return new RestTemplateBuilder() //
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken)
//                .interceptors(new AccessTokenInterceptor(tokenAccessor)) //
                .build();
    }

    @Bean
    @Qualifier("default_template")
    RestTemplate restTemplateForToken() {
        AccessTokenInterceptor accessToken = new AccessTokenInterceptor(tokenAccessor);
        return new RestTemplateBuilder()
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .build();
    }

    @Bean
    CommandLineRunner commandLineRunner(UserRepository userRepository) {
        return args -> {
            userRepository.saveAll(Arrays.asList(
                    new Users("dpi-user1", "123456", "dpi-user1@dpi.localhost", "shanxi", 28, "男", 5284.65, "admin"),
                    new Users("zhangsan", "123456", "zhangsan@gmail.com", "beijing", 23, "男", 5554.22, "admin"),
                    new Users("lisi", "123456", "lisi@gmail.com", "shanghai", 28, "男", 6886.23, "admin")
            ));
        };
    }
}
