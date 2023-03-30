package com.zitadel.user.config;

import com.zitadel.user.model.Users;
import com.zitadel.user.repository.UserRepository;
import com.zitadel.user.support.CustomUserDetailsService;
import com.zitadel.user.support.zitadel.ZitadelGrantedAuthoritiesMapper;
import com.zitadel.user.support.zitadel.ZitadelLogoutHandler;
import lombok.RequiredArgsConstructor;
import lombok.var;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
class WebSecurityConfig {

    @Value("${spring.security.oauth2.client.provider.zitadel.issuer-uri}")
    private String issuerUri;

    @Value("${spring.security.oauth2.client.registration.zitadel.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.zitadel.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.zitadel.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.registration.zitadel.scope}")
    private String[] scope;

    @Value("${webconfig.allowedOriginPatterns}")
    private String allowedOriginPatterns;

    private final ZitadelLogoutHandler zitadelLogoutHandler;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        http.cors().configurationSource(request -> {
            var cors = new CorsConfiguration();
            cors.setAllowedOriginPatterns(Arrays.asList(allowedOriginPatterns.split(",")));
            cors.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
            cors.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization", "sessionToken", "X-TOKEN", "Origin"));
            cors.setAllowCredentials(true);
            cors.validateAllowCredentials();
            return cors;
        });

        http.authorizeRequests(arc -> {
            // declarative route configuration
            arc.antMatchers("/webjars/**", "/resources/**", "/css/**", "/imgs/**", "/login**", "/login/**").permitAll();
            arc.antMatchers(HttpMethod.OPTIONS, "/**").permitAll();
            // add additional routes
            arc.mvcMatchers("/member/**").hasAnyRole("admin")
                    .anyRequest().authenticated();
        });

        // by default spring security oauth2 client does not support PKCE for confidential clients for auth code grant flow,
        // we explicitly enable the PKCE customization here.
        http.oauth2Client(o2cc -> {
            var oauth2AuthRequestResolver = new DefaultOAuth2AuthorizationRequestResolver( //
                    clientRegistrationRepository, //
                    OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI //
            );
            // Note: back-ported the OAuth2AuthorizationRequestCustomizers from Spring Security 5.7,
            // replace with original version once Spring Boot support Spring Security 5.7.
            //oauth2AuthRequestResolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

            o2cc.authorizationCodeGrant().authorizationRequestResolver(oauth2AuthRequestResolver);
        });

        http.oauth2Login(o2lc -> {
            o2lc.loginPage("/login")
                    .userInfoEndpoint()
                    .userAuthoritiesMapper(userAuthoritiesMapper())
                    .oidcUserService(oAuth2UserService());
        });


        http.formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .permitAll();


        http.logout(lc -> {
            lc.addLogoutHandler(zitadelLogoutHandler);
        });


        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, CustomUserDetailsService userDetailService)
            throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailService)
                .passwordEncoder(NoOpPasswordEncoder.getInstance())
                .and()
                .build();
    }


    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oAuth2UserService() {
        OidcUserService userService = new OidcUserService();
        return userRequest -> {
            OidcUser user = userService.loadUser(userRequest);

            System.out.printf("ZITADEL登录成功后，逻辑处理中，当前用户:%s\n", user);

            /*
             * 查询当前用户数据库，用户是否存在，如果不存在则同步用户信息到本地数据库中
             */
            Optional<Users> users = userRepository.getByName(user.getPreferredUsername());
            if (users.isPresent()) {
                Users u = users.get();
                System.out.println("查询到用户：" + u.getName() + "，登录成功");
            } else {
                System.out.println("未查询到用户：" + user.getPreferredUsername());
                System.out.println("正在进行用户《" + user.getPreferredUsername() + "》同步中...");

                LinkedHashMap<String, String> roles = (LinkedHashMap<String, String>) user.getUserInfo().getClaims().get("urn:zitadel:iam:org:project:roles");
                Set<String> roleKeys = roles.keySet();

                // TODO 未查询到用户，向用户表里同步该用户
                userRepository.save(Users.builder()
                        .name(user.getPreferredUsername())
                        .email(user.getEmail())
                        .password("123456")
                        .state((short) 1)
                        .roles(roleKeys.stream().collect(Collectors.joining(","))).build());

                System.out.println("同步用户《" + user.getPreferredUsername() + "》成功！");
            }
            return user;
        };
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(
                ClientRegistration.withRegistrationId("zitadel")
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri(redirectUri)
                        .scope(scope)
                        .authorizationUri(issuerUri + "/oauth/v2/authorize")
                        .tokenUri(issuerUri + "/oauth/v2/token")
                        .userInfoUri(issuerUri + "/oidc/v1/userinfo")
                        .jwkSetUri(issuerUri + "/oauth/v2/keys")
                        .userNameAttributeName(IdTokenClaimNames.SUB)
                        .clientName("Login with Zitadel")
                        .build()
        );
    }

    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return new ZitadelGrantedAuthoritiesMapper();
    }
}