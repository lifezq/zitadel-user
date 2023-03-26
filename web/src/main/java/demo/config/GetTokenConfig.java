package demo.config;

import demo.support.AccessTokenInterceptor;
import demo.support.TokenAccessor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class GetTokenConfig {

    private final TokenAccessor tokenAccessor;

    @Bean
    @Qualifier("default_template")
    RestTemplate restTemplateForToken(){
        AccessTokenInterceptor accessToken = new AccessTokenInterceptor(tokenAccessor);
        return new RestTemplateBuilder()
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .build();
    }
}
