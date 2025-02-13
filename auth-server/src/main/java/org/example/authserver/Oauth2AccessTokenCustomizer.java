package org.example.authserver;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class Oauth2AccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    // Here we are using the in memory user details service, but this could be any user service/repository
    private final UserDetailsService userService;

    @Override
    public void customize(JwtEncodingContext context) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getClaims().claims(claims -> {
                Object principal = context.getPrincipal().getPrincipal();

                // STARTS HERE
                User user = null;

                if (principal instanceof UserDetails) { // form login
                    user = (User) principal;
                } else if (principal instanceof DefaultOidcUser oidcUser) { // oauth2 login
                    // fetch user by email to obtain User object when principal is not already a User object
                    String email = oidcUser.getEmail();
                    user = (User) userService.loadUserByUsername(email);
                }

                if (user == null) return;
                // ENDS HERE

                Set<String> roles = AuthorityUtils.authorityListToSet(user.getAuthorities()).stream().map(c -> c.replaceFirst("^ROLE_", "")).collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
                claims.put("roles", roles);

                // I have only added the roles to the JWT here as I am using the limited fields
                // on the UserDetails object, but you can add many other important fields by
                // using your applications User class (as shown below)

                // claims.put("email", user.getEmail());
                // claims.put("sub", user.getId());
            });
        }
    }
}
