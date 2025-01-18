package org.example.authserver;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        // implementation is taken from PublicClientAuthenticationConverter
        // ---> removed the check for grant type being AUTHORIZATION_CODE
        // ---> removed the PKCE requirement
        // ---> added a check to verify if the token request is a refresh token request
        // ---> added a check to verify that the token request has no client_secret (ensure no authentication method)

        // grant_type (REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
            return null;
        }

        // client_secret (Should not be present)
        String clientSecret = request.getParameter(OAuth2ParameterNames.CLIENT_SECRET);
        if (!StringUtils.hasText(clientSecret)) {
            return null;
        }

        MultiValueMap<String, String> parameters = "GET".equals(request.getMethod()) ? getQueryParameters(request) : getFormParameters(request);

        // client_id (REQUIRED for public clients)
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        parameters.remove(OAuth2ParameterNames.CLIENT_ID);

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0])));

        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null, additionalParameters);
    }

    // helper method that can be found in OAuth2EndpointUtils
    static MultiValueMap<String, String> getQueryParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            if (queryString.contains(key) && values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }

    // helper method that can be found in OAuth2EndpointUtils
    static MultiValueMap<String, String> getFormParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            // If not query parameter then it's a form parameter
            if (!queryString.contains(key) && values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }
}
