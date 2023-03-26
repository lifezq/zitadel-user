package demo.support.zitadel;

import lombok.extern.slf4j.Slf4j;
import lombok.var;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
@Component
public class ZitadelLogoutHandler implements LogoutHandler {
    private static final Logger logger = LogManager.getLogger(ZitadelLogoutHandler.class);

    //    public static final String ZITADEL_END_SESSION_ENDPOINT = "https://accounts.zitadel.ch/oauth/v2/endsession";
    @Value("${spring.security.oauth2.client.provider.zitadel.issuer-uri}/oidc/v1/end_session")
    public String ZITADEL_END_SESSION_ENDPOINT;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication auth) {

        if (auth.getPrincipal() instanceof OidcUser) {

            var principal = (DefaultOidcUser) auth.getPrincipal();
            var idToken = principal.getIdToken();

            log.debug("Propagate logout to zitadel for user. userId={}", idToken.getSubject());

            var idTokenValue = idToken.getTokenValue();
            var defaultRedirectUri = generateAppUri(request);
            var logoutUrl = createZitadelLogoutUrl(idTokenValue, defaultRedirectUri);

            try {
                response.sendRedirect(logoutUrl);
            } catch (IOException e) {
                log.error("Could not propagate logout for user to zitadel. userId={}", idToken.getSubject(), e);
            }
        } else {

            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
                if (logger.isDebugEnabled()) {
                    logger.debug(LogMessage.format("Invalidated session %s", session.getId()));
                }
            }

            SecurityContext context = SecurityContextHolder.getContext();
            SecurityContextHolder.clearContext();
            context.setAuthentication((Authentication) null);
        }
    }

    private String generateAppUri(HttpServletRequest request) {
        var hostname = request.getServerName() + ":" + request.getServerPort();
        var isStandardHttps = "https".equals(request.getScheme()) && request.getServerPort() == 443;
        var isStandardHttp = "http".equals(request.getScheme()) && request.getServerPort() == 80;
        if (isStandardHttps || isStandardHttp) {
            hostname = request.getServerName();
        }
        return request.getScheme() + "://" + hostname + request.getContextPath();
    }

    private String createZitadelLogoutUrl(String idTokenValue, String postRedirectUri) {
        return ZITADEL_END_SESSION_ENDPOINT + //
                "?id_token_hint=" + idTokenValue //
                + "&post_logout_redirect_uri=" + postRedirectUri;
    }
}
