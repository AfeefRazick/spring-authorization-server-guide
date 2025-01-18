# Spring Authorization Server : 0-90 (You almost made it to prod!!)

This series is designed to take you 90% of the way with Spring Authorization Server,
covering essential concepts and implementations. The remaining 10% largely involves
moving in-memory stores to durable storage like a database, which is quite straight
forward and so it will not be covered. The focus here is on mastering core Spring
Authorization Server principles.

My motivation to write this series is the immense amount of time I had to invest
in achieving certain aspects of this flow. Much of that time was spent due to some
misunderstanding of the bigger picture, as most online guides focused only on specific
subtopics and were not very useful beyond a tutorial level. Because of this,
you may find this article lengthy and overly in-depth, but I promise to keep it as
concise as possible.

Note: This is not a beginner's guide. The content assumes familiarity with Spring
and related technologies to maintain focus on the Spring Authorization Server.

- Part 1 - Oauth2 Authorization Code Flow - Confidential Client
- Part 2 - Public Client PKCE Authorization code flow (with refresh tokens)
- Part 3 - Social login (with customized jwt)
- Part 4 - Customized login page

You can find all the code for this series in this Github repo.
[https://github.com/AfeefRazick/spring-authorization-server-guide](https://github.com/AfeefRazick/spring-authorization-server-guide)

## Prerequisites

This guide assumes you:

- Have a good understanding of Spring and how it works.
- Are familiar with OAuth2, specifically the [Authorization Code Grant Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow).

Despite the prerequisites, I’ll give a quick explanation of what we’re trying
to achieve to clear up some common misconceptions—ones I personally struggled
with when starting out.

Our resource servers (e.g., books-service) should require authentication
using an access token, likely a JWT. The web-app, whether a SPA (public client)
or SSR (confidential client), needs authentication to communicate with the resource
servers. Since OAuth2 is delegated authorization, the auth server can run independently
in a separate container, cluster, or domain.

Firstly, it's important to understand that the approach for a public client differs
from that of a confidential client. Most security experts, including the Spring Security
team, strongly recommend that public clients should not participate in the OAuth2
flow (I share the same opinion).
Instead we must use confidential clients to communicate with the authorization server.
Here’s why:

The OAuth2 authorization code flow requires the oauth2 client to present a
"CLIENT SECRET" to identify itself. This is crucial because the authorization server
can have many clients (e.g., BFF server, terminal client, third-party API user).
The client secret must be securely stored, which can only be done in a confidential
client. Public clients, like those in browsers, have no secure way to store secrets
(local/session storage are accessible to javascript, and HTTP-only cookies can only
be used securely across the same domain name, which is not likely to be the case
in a delegated authorization environment).
As a result, public clients must use the [PKCE flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce),
which does not require a client secret.

Additionally, once a public client is authorized, it cannot securely store sensitive
OAuth2 tokens (e.g., access/refresh tokens).

Furthermore, once an access token is granted, it cannot be revoked until it expires,
which means once it has been given out to a public client, there is no way to invalidate
it.

With a confidential client, the OAuth2 authorization code flow mainly occurs on the
server side, with the browser only used to provide credentials on the auth server
login page. The confidential client maintains a session token with the browser,
exchanging it for an OAuth2 token on each request, which is then passed to the
resource servers. For a deeper dive into this pattern, check out this article
on the [benefits of this pattern](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2)

In fact, if you inspect the application tab of websites from major tech companies
like Google, you’ll notice they don’t store JWTs or access tokens in the browser.
Instead, they use session tokens.

Now,... maintaining stateful sessions across servers introduces its own scalability
challenges. There are many solutions for this like spring's own [Spring Session](https://spring.io/projects/spring-session).
However, that is a topic for another day.

In Part 1, we’ll set up the OAuth2 authorization code flow with a confidential
OAuth2 client. For simplicity, I’ve chosen an API gateway application as the
confidential client, but it could also be a BFF.
Parts 2, 3, and 4 in the series are independent, so you can choose them based
on your needs.

DISCLAIMER: Spring authorization server requires quite a bit of effort and
tinkering to be bought up and running for a production environment.

## Part 1 - Spring Authorization Server - Oauth2 Authorization Code Flow - Confidential Client

The branch for this guide is `part-1/oauth2-authorization-code-flow`.

I’m starting with a Gradle Groovy Spring Boot boilerplate, but a Maven project
works just as well. Here are my default dependencies:

```gradle
// build.gradle
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
}
```

The first step is to add some Spring dependencies. I’ll also include Lombok
for convenience.

```gradle
// build.gradle
dependencies {
    // ...other dependencies
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation "org.springframework.boot:spring-boot-starter-security"
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-authorization-server'
    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
}
```

Let’s specify the port for our application:

```yml
# application.yml
server:
  port: 9000

```

Now we can start configuring our authorization server. First, let’s define our
client repository, which will manage the clients that our authorization server
provides authorization to. There are many settings you can configure for each
client, but below is a minimal configuration that should work fine.

In a production environment, this repository should ideally manage and store
registered clients in a database. However, for this demo, we will use an
in-memory store. 🤡

```java
// SecurityConfig.java
@Configuration
public class SecurityConfig {

    private final static String GATEWAY_CLIENT_ID = "gateway-client";
    private final static String GATEWAY_CLIENT_HOST_URL = "http://localhost:8080";

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // @formatter:off
        RegisteredClient webClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId(GATEWAY_CLIENT_ID)
                .clientSecret(passwordEncoder().encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(GATEWAY_CLIENT_HOST_URL + "/login/oauth2/code/" + GATEWAY_CLIENT_ID)
                .postLogoutRedirectUri(GATEWAY_CLIENT_HOST_URL + "/logout")
                .scope(OidcScopes.OPENID)  // openid scope is mandatory for authentication
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .build();
        // @formatter:on
        return new InMemoryRegisteredClientRepository(webClient);
    }
}
```

Next, we configure the Spring Security filter chains.

- The first filter chain is for authorization server-specific configurations.
- The second filter chain handles application-specific configurations, such
as additional endpoints.

```java
// SecurityConfig.java
@Bean
@Order(1) // security filter chain for the authorization server
public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    // @formatter:off

    // applyDefaultSecurity method deprecated as of spring security 6.4.2, so we replace it with below code block
    // -- STARTS HERE
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
            OAuth2AuthorizationServerConfigurer.authorizationServer();

    http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, authorizationServer ->
                    authorizationServer.oidc(Customizer.withDefaults()) // enable openid connect
            )
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
    // -- ENDS HERE

    http
            .exceptionHandling((exceptions) -> // If any errors occur redirect user to login page
                    exceptions.defaultAuthenticationEntryPointFor(
                            new LoginUrlAuthenticationEntryPoint("/login"),
                            new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                    )
            )
            // enable auth server to accept JWT for endpoints such as /userinfo
            .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
    // @formatter:on

    return http.build();
}

@Bean
@Order(2) // security filter chain for the rest of your application and any custom endpoints you may have
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    // @formatter:off
    http
            .formLogin(Customizer.withDefaults()) // Enable form login
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
    // @formatter:on

    return http.build();
}
```

Next, define a PasswordEncoder bean to salt and hash passwords:

```java
// SecurityConfig.java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

To enable login functionality, provide a user store with user credentials.
For this guide, we'll use an in-memory user store, but you can adapt it to
fetch user details from a database if needed.

```java
// SecurityConfig.java
@Bean
UserDetailsService users() {
    // @formatter:off
    UserDetails user = User.builder()
            .username("prime")
            .password("agen")
            .passwordEncoder(passwordEncoder()::encode)
            .roles("USER")
            .build();
    // @formatter:on
    return new InMemoryUserDetailsManager(user);
}
```

Now, let’s test the auth server.

1. Open your browser and navigate to the root of the server (e.g., localhost:9000/).
You should be redirected to the login page since you're not authenticated.
2. Enter your credentials on the login page.
3. After logging in, you should see the white label error screen:

This whitelabel error appears because there’s no resource at the root URL.
It’s simply the default HTML returned for a 404 error.

So far, we’ve only interacted with the auth server itself. No tokens have
been issued because we haven’t logged in on behalf of a client application.
Instead, the auth server has managed our identity using its own session token,
which is established between the browser and the server. By default, Spring
uses the JSESSIONID token, which is produced by Tomcat.

I’ve set up a separate gradle project called api-service which includes an API gateway
(confidential OAuth2 client) and a books-service (resource server).

Starting with the Resource Server. We’ll add the following dependencies:

```gradle
// build.gradle
dependencies {
    // ... other dependencies
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
    // lombok for convenience
    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
}
```

We’ll run it on port `8081`.

Since we've added the OAuth2 resource server dependency, all our endpoints are
authenticated by default. Therefore, the resource server expects authentication.
We will now configure the resource server to accept JWT for authentication.
To verify the JWT, it needs to know the public keys, so we’ll point the resource
server to the authorization server.

```yml
# application.yml
server:
  port: 8081

spring:
  # ... other configuration
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:9000
```

I have a simple REST controller with one endpoint, /books. I've included
some logic to extract the username and JWT token for demonstration purposes.

```java
// BookResource.java
@RestController
@RequiredArgsConstructor
public class BookResource {

    @GetMapping("/books")
    public ResponseEntity<String> getBooks(Authentication authentication) { // authentication parameter is not necessary
        // The lines below are purely to demonstrate the existence of the jwt, you do not need them for your endpoints
        assert authentication instanceof JwtAuthenticationToken;
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
        String username = authentication.getName();
        String jwtString = jwtAuthenticationToken.getToken().getTokenValue();

        return ResponseEntity.ok("Hi " + username + ", here are some books [book1, book2],  " + " also here is your jwt : " + jwtString);
    }
}
```

Let's set up our [API Gateway as an OAuth2 confidential client](https://www.baeldung.com/spring-cloud-gateway-oauth2).

```gradle
// build.gradle
dependencies {
    // ... other dependancies
    implementation 'org.springframework.cloud:spring-cloud-starter-gateway:4.2.0'
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
}
```

We'll run our API Gateway on port `8080`

Our API Gateway is quite simple, so we don't need to write any code.
Configuring it through `application.yml` is enough.

First, we'll define our routes, and we only have one: the user service.

```yml
# application.yml
spring:
  # ...other configuration
  cloud:
    gateway:
      routes:
        - id: book-service
          uri: http://localhost:8081
          predicates:
            - Path=/books/**
          filters:
            - TokenRelay # Token relay filter appends the oauth (or jwt) token to request header before forwarding requests
 
```

Next, we can add our OAuth2 client configuration.

```yml
# application.yml
spring:
  # ... other configuration
  security:
    oauth2:
      client:
        provider:
          platform-auth-server:
            issuer-uri: http://localhost:9000
        registration:
          gateway-client:
            provider: platform-auth-server
            client-id: gateway-client
            client-secret: "secret"
            client-authentication-method: client_secret_basic
            authorization-grant-type: authorization_code
            redirect-uri: http://localhost:8080/login/oauth2/code/gateway-client
            scope:
              - openid
              - profile
              - email
```

Once the user has been authorized, just like our Auth Server, the API Gateway also
issues a JSESSIONID to the user and stores the OAuth2/JWT tokens in the session,
associating them with the JSESSIONID. In subsequent requests, the JSESSIONID is
sent as an HTTP-only cookie.

However, our downstream resource server, books-service, is stateless and has no
knowledge of this session and can only verify the authenticity of the JWT. This
is where the token relay filter comes in. It exchanges the session token with the
associated OAuth2 tokens and appends them to the request header before passing
the request to downstream services

Although we have all our applications configured correctly, if we try the login flow,
we will encounter some errors. This is because, although our auth server and API
gateway are running on different ports, the browser sees them both as one application
since they are both running on the same domain, 'localhost'.

Both the API gateway and the auth server use the same token name by default, 'JSESSIONID'.
As a result, whenever the API gateway sets its session token, the browser overrides
the session token set by the auth server, and vice versa.

To fix this, we can go ahead and run our auth server on a different domain name,
like `http://127.0.0.1`. `localhost` is simply an alias for this IP address,
but the browser still views them as two different domains, so it serves our purpose.
We will need to tell the auth server its own address.

```yml
# application.yml (auth-server)
server:
  port: 9000
  address: 127.0.0.1

```

Then, we replace any mention of the auth server URL in the other applications.

```yml
# application.yml (api-gateway)
spring:
  # ... other configuration
    platform-auth-server:
      issuer-uri: http://127.0.0.1:9000

```

```yml
# application.yml (books-service)
spring:
  # ... other configuration
    resourceserver:
      jwt:
        issuer-uri: http://127.0.0.1:9000

```

If you test this setup now, you should be able to access the resource server's `/books`
endpoint via the API Gateway at `localhost:8080`. You will be redirected to the Auth
Server's login screen. After entering your credentials, you will be redirected back
to the `/books` endpoint. All subsequent requests to this endpoint will remain authenticated
without requiring another login at the Auth Server.

Let's copy the JWT token you see on the `/books` endpoint and paste it into [jwt.io](https://jwt.io/).
You’ll notice that the decoded JWT payload appears as follows:

```json
{
  "sub": "prime",
  "aud": "gateway-client",
  "nbf": 1735996802,
  "scope": [
    "openid",
    "profile",
    "email"
  ],
  "iss": "http://127.0.0.1:9000",
  "exp": 1735997102,
  "iat": 1735996802,
  "jti": "4dde1b42-5379-4b59-b97b-dd522e545ec7"
}
```

This is fine, but typically, we want to store more information in the JWT.
Let’s explore how to add custom claims.

To customize our JWT, we need to provide an implementation of `OAuth2TokenCustomizer`
to the Authorization Server.

```java
// Oauth2AccessTokenCustomizer.java
@RequiredArgsConstructor
@Component
public class Oauth2AccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getClaims().claims(claims -> {
                Object principal = context.getPrincipal().getPrincipal();
                User user = (User) principal;

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
```

Let's define a token generator bean in the security configuration class. This will
be a delegating token generator, enabling us to generate the appropriate token type
for each scenario (e.g., JWT access token, refresh token, opaque token, OIDC token,
etc.). We'll pass the access token generator, along with the customizer we just
defined, into this token generator.

```java
// SecurityConfig.java
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {
    // ... other configuration

    private final Oauth2AccessTokenCustomizer oauth2AccessTokenCustomizer;

    @Bean
    OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtAccessTokenGenerator = new JwtGenerator(jwtEncoder);
        jwtAccessTokenGenerator.setJwtCustomizer(oauth2AccessTokenCustomizer);

        return new DelegatingOAuth2TokenGenerator(jwtAccessTokenGenerator);
    }
}
```

Let's run our auth server again and check the new JWT.

```json
{
  "sub": "prime",
  "aud": "gateway-client",
  "nbf": 1735999618,
  "scope": [
    "openid",
    "profile",
    "email"
  ],
  "roles": [
    "USER"
  ],
  "iss": "http://127.0.0.1:9000",
  "exp": 1735999918,
  "iat": 1735999618,
  "jti": "a5d3092c-de55-465e-8153-a4341e4d8754"
}
```

As you can see, the `roles` field has been added with the "User" role for prime.

You can technically run this setup; however, restarting the servers will result in
lost login information. Additionally, this setup is not suitable for scaling with
multiple instances of the API Gateway or Authorization Server. To make it production-ready,
move the following to durable storage:

- Registered Client Repository: for OAuth2 clients
- UserDetailsService: for user login store
- OAuth2AuthorizationService: for tokens
- JWK Source: for RSA keys pairs

## Part 2 - Spring Authorization Server - Public Client PKCE Authorization code flow  (with refresh tokens)

If you haven’t read [Part 1](https://medium.com/@afeefrazickamir/spring-authorization-server-0-90-03d996d5c5a7),
I recommend starting there, as this guide is part of a series and builds upon
the concepts introduced earlier.

You can find all the code for this series in this [Github repo](https://github.com/AfeefRazick/spring-authorization-server-guide).
The branch for this guide is `part-2/public-client-pkce-auth-code`.

While [PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce),
is a recommendation in the current OAuth 2.0 standard, it becomes a requirement
under the OAuth 2.1 specification.

As explained in Part 1, this section will cover configuring PKCE for public clients,
as the client_secret_basic authentication method is not secure for such clients.

Although it is generally not recommended for public clients to participate in the
OAuth2 flow, obtaining an access token in the browser is permitted by Spring Authorization
Server and other implementations of the RFC specification. This allowance is based
on the expectation that access tokens are designed to have short lifespans.

Although this is the case, requiring users to log in every 5 minutes is not user-friendly.
To address this, we need a way to silently refresh the access token without user
intervention.

Some interesting solutions exist, such as those implemented by frontend libraries
like oidc-client-ts. These libraries use an iframe to perform silent token refreshes.
Instead of relying on a refresh token, the iframe executes the authorization code
flow by redirecting to the authorization server. The existing session
(via session cookies) on the auth server is used to issue a new access token without
requiring the user to log in again.

This solution once again requires the authorization server to be on the same domain
as the client. If they are not, there are workarounds, but they introduce increased
security vulnerabilities. For more details, you can refer to this
[Stack Overflow discussion](https://stackoverflow.com/questions/72026554/silent-renew-doesnt-work-on-spring-authorization-server-and-react-client).

Ultimately, we must resort to allowing the SPA to obtain a refresh token
(a feature enabled by the Spring team in 2024—[here is the PR](https://github.com/spring-projects/spring-authorization-server/pull/1432)).
However, storing the refresh token in local storage or session storage is not secure
and is strongly discouraged. The impact of a stolen refresh token can be far more
detrimental due to its longer lifespan.

To mitigate these risks, techniques such as rotating refresh tokens—where a new refresh
token is issued with each refresh request—can be implemented. This approach limits
the potential damage of a stolen refresh token by invalidating old tokens upon use.

Lets get started.
First lets configure CORS to allow requests from the public client to the authorization
server.

```java
// SecurityConfig.java
private final static String PUBLIC_CLIENT_HOST_URL = "http://localhost:5173";

@Bean
CorsConfigurationSource corsConfigurationSource() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.addAllowedOrigin(PUBLIC_CLIENT_HOST_URL);
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    config.setAllowCredentials(true);
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

Ensure CORS is enabled in both security filter chains to apply the default CORS configuration.

```java
// SecurityConfig.java
http
      // ... other configuration
      .cors(Customizer.withDefaults())
```

Add the OAuth2 public client to the `RegisteredClientRepository`. Ensure the authentication
method is NONE and PKCE is enabled.

```java
// SecurityConfig.java

private final static String PUBLIC_CLIENT_ID = "public-client";

// @formatter:off
RegisteredClient publicWebClient = RegisteredClient
        .withId(UUID.randomUUID().toString())
        .clientId(PUBLIC_CLIENT_ID)
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // authentication method set to 'NONE'
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .redirectUri(PUBLIC_CLIENT_HOST_URL + "/callback")
        .postLogoutRedirectUri(PUBLIC_CLIENT_HOST_URL + "/logout")
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.PROFILE)
        .scope(OidcScopes.EMAIL)
        .clientSettings(ClientSettings.builder().requireProofKey(true).build()) // enable PKCE
        .build();
// @formatter:on

return new InMemoryRegisteredClientRepository(webClient, publicWebClient);
```

With this setup, our SPA can now obtain access tokens via the authorization code
flow. Next, we need to enable the SPA to obtain refresh tokens.

Spring provides a default implementation of the [OAuth2RefreshTokenGenerator](https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/token/OAuth2RefreshTokenGenerator.java).
However, this implementation includes a condition that prevents issuing refresh
tokens to public clients (when the authentication method is null).

To address this, we can define a custom implementation of `OAuth2RefreshTokenGenerator`,
omitting the restriction on issuing refresh tokens to public clients.

```java
// OAuth2PublicClientRefreshTokenGenerator.java
public class OAuth2PublicClientRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    @Nullable
    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
    }
}
```

Next, we need to add our custom refresh token generator to the `DelegatingOAuth2TokenGenerator`.

```java
// SecurityConfig.java
@Bean
OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
    JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
    JwtGenerator jwtAccessTokenGenerator = new JwtGenerator(jwtEncoder);
    jwtAccessTokenGenerator.setJwtCustomizer(oauth2AccessTokenCustomizer); // jwt customizer from part 1

    return new DelegatingOAuth2TokenGenerator(
                      jwtAccessTokenGenerator,
                      new OAuth2PublicClientRefreshTokenGenerator() // add customized refresh token generator
    );
}
```

With this, our public client should now be able to receive refresh tokens.

To test this, let’s set up a SPA web app as the public client. The [oidc-client-ts](https://github.com/authts/oidc-client-ts)
library is a popular, framework-agnostic OAuth2 library for JS/TS projects.
Since React is one of the most widely used frontend frameworks, I will use
it for this example. For better integration, we’ll use [react-oidc-context](https://github.com/authts/react-oidc-context),
a wrapper around `oidc-client-ts` that simplifies managing authentication
state and lifecycle.

I’ll follow the [Getting Started](https://github.com/authts/react-oidc-context/blob/main/README.md)
guide provided by them.

First, let’s install the necessary dependencies:

```bash
npm install oidc-client-ts react-oidc-context
```

Next, let’s add our OIDC configuration and the `AuthProvider` to `main.tsx`.
This will set up the authentication context for our application:

```typescript
// main.tsx
const CLIENT_ID = "public-client";
const AUTH_SERVER_URL = "http://127.0.0.1:9000";
const HOST_URL = window.location.origin;

const oidcConfig: UserManagerSettings = {
  authority: AUTH_SERVER_URL,
  client_id: CLIENT_ID,
  redirect_uri: HOST_URL + "/callback",
  response_type: "code",
  scope: "openid profile email",
};

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthProvider {...oidcConfig}>
      <App />
    </AuthProvider>
  </StrictMode>,
);
```

Next, let's add some lifecycle methods to `App.tsx`.

```typescript
// App.tsx
import { useAuth } from "react-oidc-context";

function App() {
  const auth = useAuth();

  switch (auth.activeNavigator) {
    case "signinSilent":
      return <div>Signing you in...</div>;
    case "signoutRedirect":
      return <div>Signing you out...</div>;
  }

  if (auth.isLoading) {
    return <div>Loading...</div>;
  }

  if (auth.error) {
    return <div>Oops... {auth.error.message}</div>;
  }

  if (auth.isAuthenticated) {
    return (
      <div>
        Hello {auth.user?.profile.sub}{" "}
        <button onClick={() => void auth.removeUser()}>Log out</button>
      </div>
    );
  }

  return <button onClick={() => void auth.signinRedirect()}>Log in</button>;
}

export default App;
```

When we run our React app and click the login button, we're redirected to the
auth server login page. After entering our credentials, we return to the callback
page. If you check the network tab, you'll see that the `/oauth2/token` endpoint
is hit, where the SPA sends the authorization code as a parameter. The response
includes a refresh token.

However, if we attempt to obtain an access token by hitting the `/oauth2/token`
endpoint and providing the refresh token, the request will fail, and we’ll be
redirected to `/login` on the auth server. The oidc-client-ts library, when
`automaticSilentRenew` is set to true, will attempt to silently renew the token
1 minute before the access token expires. By default, the access token's
time-to-live is 5 minutes. To observe this behavior, we'll reduce the `accessTokenTimeToLive`
to about 70 seconds in the token settings of the auth server.

```java
// SecurityConfig.java
RegisteredClient publicWebClient = RegisteredClient
        // ... other configuration
        .tokenSettings(
                TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(70))
                        .build()
        )
```

You can also test this via Postman or cURL to confirm. (Be sure to replace the
relevant values, such as authserverurl, clientID, and refresh_token, with your own.)

```bash
curl --location 'http://127.0.0.1:9000/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Cookie: JSESSIONID=BE95D161C4EB1F5D45FEAE1AE5081643' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'client_id=public-client' \
--data-urlencode 'refresh_token=SInTDYU8XZcTQtFyQ5LzREXRTFG3f9m85ybguc71WgeJ10akXnht2JXS3gJMEecVwGqKPctFSiOhUlka7Dl-uRhRR8Tfb1ElKipyhhlEftDghI8Dys5FXPzGgVJB9pRt'
```

This is because, although we have configured our authorization server to issue
a refresh token to a public client, the default behavior of the Spring Authorization
Server is to reject a token refresh attempt from a public client. An access token
cannot be refreshed via a refresh token when the authentication_method is set to
NONE. In this case, a public client can only obtain a new access token by performing
the authorization code flow again.

If you're familiar with Spring Security architecture, you'll know that there is one
[authentication manager](https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-providermanager)
per filter chain. This authentication manager can have a list
of authentication converters and providers, where the authentication converters run
first to extract an authentication token from the HTTP servlet request, and the
providers then verify this token.

By default, Spring Security provides a [PublicClientAuthenticationConverter](https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/web/authentication/PublicClientAuthenticationConverter.java)
and a [PublicClientAuthenticationProvider](https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/authentication/PublicClientAuthenticationProvider.java).
These implementations allow a public client to obtain an access token via the PKCE
authorization code flow. However, they do not allow refresh tokens to be used for
generating access tokens for public clients (ClientAuthenticationMethod.NONE).
Therefore, we will need to provide additional implementations of the converter and
provider to enable this behavior. I will use the existing implementations mentioned
above and adjust them to support this functionality.

For the converter, we'll adapt it for the refresh token grant type instead of the
authorization code flow, which also means removing the PKCE requirement.

```java
// PublicClientRefreshTokenAuthenticationConverter.java
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
```

For the provider, the only adjustment needed is to remove the PKCE requirement.

```java
// PublicClientRefreshTokenAuthenticationProvider.java
@Slf4j
public final class PublicClientRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    private final RegisteredClientRepository registeredClientRepository;

    public PublicClientRefreshTokenAuthenticationProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // implementation is taken from PublicClientAuthenticationProvider
        // ---> removed the PKCE requirement

        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

        if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }

        String clientId = clientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }

        log.trace("Retrieved registered client");

        if (!registeredClient.getClientAuthenticationMethods().contains(clientAuthentication.getClientAuthenticationMethod())) {
            throwInvalidClient("authentication_method");
        }

        log.trace("Validated client authentication parameters");

        log.trace("Authenticated public client");

        return new OAuth2ClientAuthenticationToken(registeredClient, clientAuthentication.getClientAuthenticationMethod(), null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static void throwInvalidClient(String parameterName) {
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Client authentication failed: " + parameterName, ERROR_URI);
        throw new OAuth2AuthenticationException(error);
    }
}
```

Let’s add the converter and provider to our authorization server configuration
within the authorization server security filter chain.

```java
// SecurityConfig.java
http
      // ... other configuration
      .with(authorizationServerConfigurer, authorizationServer ->
              authorizationServer
                      // ... other configuration
                      .clientAuthentication(clientAuthenticationConfigurer ->
                             clientAuthenticationConfigurer
                                     .authenticationConverter(new PublicClientRefreshTokenAuthenticationConverter())
                                     .authenticationProvider(
                                             new PublicClientRefreshTokenAuthenticationProvider(
                                                     registeredClientRepository(),
                                                     new InMemoryOAuth2AuthorizationService() // replace with your AuthorizationService implementation if you have one
                                             )
                                     ) 
                      )
      )
```

Now, restart the auth server, and you should be able to verify that calls to the
`/oauth2/token` endpoint with the refresh token grant type are successful.

Earlier, we discussed how rotating refresh tokens on each refresh can mitigate
security risks. We can achieve this by disabling the reuse of refresh tokens
in the `public-client`'s OAuth2 client token settings.

```java
// SecurityConfig.java
RegisteredClient publicWebClient = RegisteredClient
        // ... other configuration
        .tokenSettings(
                TokenSettings.builder()
                        .reuseRefreshTokens(false)
                        .build()
        )
```

We’ve now achieved PKCE flow with refresh tokens. However, there are a few
improvements we can make on the SPA.
I won’t go into detail as it's outside the scope of this discussion.

- You can use `onSigninCallback` to remove the leftover parameters from the URL.
- react-oidc-context provides an HOC, `withAuth`, which can be used to implement
private routes.
- Return the user to the page they were on (or attempting to access) before redirection:
There are several ways, a simple and straightforward approach is to define the `onBeforeSignin`
argument on the `withAuth` HOC to store the current pathname in local storage.
Then, in onSigninCallback or on the callback page, you can retrieve and remove
the pathname from local storage and navigate to it.

As mentioned earlier, Spring Authorization Server is not primarily designed with
this flow in mind, so some issues remain. While we’ve enabled support for both
public and confidential clients, other areas of the OAuth2 spec, like token revocation,
will require similar custom configurations. I hope this guide prepares you for any
additional configurations you may need.

## Part 3 - Spring Authorization Server - Social login (with customized jwt)

If you haven’t read [Part 1](https://medium.com/@afeefrazickamir/spring-authorization-server-0-90-03d996d5c5a7),
I recommend starting there, as this guide is part of a series and builds upon the
concepts introduced earlier (Part 2 is not required for this part).

You can find all the code for this series in this [Github repo](https://github.com/AfeefRazick/spring-authorization-server-guide).
The branch for this guide is `part-3/oauth2-social-login`.

So far, users log in by entering their username and password, where the username
is typically a unique email address. However, many users prefer social login for
email-based identity verification.

To enable social login in Spring Authorization Server, start by setting up the
authorization server as described in Part 1. If you don’t want to support username-password
login, you can skip form login. (Omit `.formLogin()` in security filter chain)

For this guide, we’ll use Google as the OAuth2 provider since it’s the most popular
choice.

First, register your application as an OAuth2 client with the provider. This involves
obtaining a client ID and secret pair. The process varies by provider, so I won’t
go into detail. For Google, you can refer to these resources:

- [https://developers.google.com/identity/protocols/oauth2](https://developers.google.com/identity/protocols/oauth2),
- [https://support.google.com/cloud/answer/6158849?hl=en](https://support.google.com/cloud/answer/6158849?hl=en)

It's crucial to add the authorization server's redirect URL to our OAuth2 provider.
If you've been following along, in Part 1, we configured the authorization server
to run on `127.0.0.1`. We can include this URL in the list of authorized redirect
URIs on Google.

As mentioned earlier, the default redirect URI format used by Spring Authorization
Server is `/login/oauth2/code/{registrationId}`, so we need to add `http://127.0.0.1:9000/login/oauth2/code/google`
as the redirect URI.

Similar to how our SPA Web App and API Gateway act as OAuth2 clients to our authorization
server, our authorization server will now function as an OAuth2 client to an external
authorization provider—in this case, Google.

To enable this functionality, we need to add the OAuth2 client dependency to our
authorization server.

```gradle
// build.gradle
dependencies {
    // ... other dependencies
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
}
```

Next, we can add the OAuth2 client configuration to our `application.yml`.
Google requires minimal configuration since it is included in the [CommonOauth2Provider](https://github.com/spring-projects/spring-security/blob/main/config/src/main/java/org/springframework/security/config/oauth2/client/CommonOAuth2Provider.java)
enum provided by Spring Security.

For other OAuth2 providers, you may need to specify additional properties.
Refer to this [list of properties](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-boot-property-mappings)
for details. Replace the client Id and secret with the ones you obtained (Ofcourse,
the keys below wont work as I have deleted them).

```yml
# application.yml (auth-server)
spring:
  # ... other configuration
  security:
    oauth2:
      client:
        registration:
          google:
            clientId: 432843073336-25dti6760u9drsjee2rmuho3au9ph90n.apps.googleusercontent.com # replace with your client id
            clientSecret: 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 # replace with your client secret
            authorization-grant-type: authorization_code
```

Next, we need to enable OAuth2 login in our default security filter chain.

```java
// SecurityConfig.java
@Bean
@Order(2)
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    // @formatter:off
    http
            // ... other configuration
            .oauth2Login(Customizer.withDefaults()) // Enable oauth2 federated identity login
    // @formatter:on

    return http.build();
}
```

Let's add another user to our user store with a username matching the email we’ll
use to log in. This ensures a user account already exists for that email (Make sure
you replace my email with the email you will use to login).

Alternatively, you can create a new account when a user logs in for the first
time by implementing an [AuthenticationSuccessHandler](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-social-login.html#advanced-use-cases-capture-users).

```java
// SecurityConfig.java
@Bean
UserDetailsService users() {
    // ... other users

    // @formatter:off
    UserDetails me = User.builder()
            .username("afeefrazickamir@gmail.com")
            .password("pass")
            .passwordEncoder(passwordEncoder()::encode)
            .roles("USER", "ADMIN")
            .build();
    // @formatter:on

    return new InMemoryUserDetailsManager(user, me);
}
```

Next, let’s revisit the OAuth2 JWT token customizer we implemented earlier.
For form login, the JWT context uses a `UserDetails` principal stored in our repository.
However, for OAuth2 social login, the JWT context contains information from the
external authorization provider—in this case, Google.

To ensure the JWTs issued and used across our application have a consistent structure,
regardless of the authorization method, we’ll make some small tweaks.

```java
// Oauth2AccessTokenCustomizer.java
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
```

Since the user details service bean from Part 1 is already defined in the security
configuration, we need to avoid a cyclic dependency error. To do so, we’ll remove
the injection of the `Oauth2AccessTokenCustomizer` bean and instantiate it manually.

```java
// SecurityConfig.java
@Bean
OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
    JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
    JwtGenerator jwtAccessTokenGenerator = new JwtGenerator(jwtEncoder);
    jwtAccessTokenGenerator.setJwtCustomizer(new Oauth2AccessTokenCustomizer(users())); // instantiate manually to prevent cyclic bean dependency

    return new DelegatingOAuth2TokenGenerator(jwtAccessTokenGenerator);
}
```

Now, if we rerun all our applications and navigate to `localhost:8080/books`,
we should be redirected to the login page on the auth server, where Google
should appear as an OAuth2 login option.

Upon clicking "Login", we should be able to authorize via the authorization provider
and finally be redirected back to the books page. If you encounter an error, check
the error message, your credentials, or the redirect URI in the console, as one of
them may be incorrect.

Now that we have the JWT displayed on the `/books` page, let's copy and paste it
into [jwt.io](jwt.io). To demonstrate the role of the JWT customizer in these
different login methods, restart the servers and also log in using username-password.
When we paste the JWT into jwt.io, we can see that the `roles` we set are present
in both tokens. However, the `sub` field, which is set by default using the principal
name, differs because of the variation in the JWT context.

- Google OAuth2 Login JWT Payload

```json
{
  "sub": "113406613444429860426",
  "aud": "gateway-client",
  "nbf": 1736841840,
  "scope": [
    "openid",
    "profile",
    "email"
  ],
  "roles": [
    "ADMIN",
    "USER"
  ],
  "iss": "http://127.0.0.1:9000",
  "exp": 1736842140,
  "iat": 1736841840,
  "jti": "d272d8a5-17a3-46c5-ba9f-6815d2c97c64"
}
```

- Username-Password Login JWT Payload

```json
{
  "sub": "afeefrazickamir@gmail.com",
  "aud": "gateway-client",
  "nbf": 1736841765,
  "scope": [
    "openid",
    "profile",
    "email"
  ],
  "roles": [
    "ADMIN",
    "USER"
  ],
  "iss": "http://127.0.0.1:9000",
  "exp": 1736842065,
  "iat": 1736841765,
  "jti": "7113f1fa-34f5-4e0b-aa63-b4cde40ed180"
}
```

Therefore, to maintain JWT consistency, we need to set such fields using
values from the user repository.

Our login page doesn't look too great, though. In [Part 4](part4link),
we'll cover customizing it.

## Part 4 - Spring Authorization Server - Customized login page

If you haven’t read [Part 1](https://medium.com/@afeefrazickamir/spring-authorization-server-0-90-03d996d5c5a7),
I recommend starting there, as this guide is part of a series and builds upon
the concepts introduced earlier (Part 2 and 3 is not required for this part).

You can find all the code for this series in this [Github repo](https://github.com/AfeefRazick/spring-authorization-server-guide).
The branch for this guide is `part-4/customized-login-page`

So far, we’ve been using Spring’s default login page, and it looks pretty bad.

In this guide, I’ll customize the login page for form login (username-password)
and OAuth2 login (social providers like Google). If your auth server doesn’t need
one of these, feel free to skip it.

Since we only need a single page and the login page isn’t complex, we’ll use
Thymeleaf—it’s more than enough. Let’s start by adding the Thymeleaf dependency
to the auth server.

```gradle
// build.gradle
dependencies {
    // ... other dependencies
    implementation 'org.springframework.boot:spring-boot-starter-thymeleaf'
}
```

I’m no designer, so I grabbed a design from online. Source: [https://www.justinmind.com/blog/inspiring-website-login-form-pages/](https://www.justinmind.com/blog/inspiring-website-login-form-pages/)

After running it through [v0](https://v0.dev) and making a few tweaks in the v0 chat,
it’s close enough to the original design. This works for me since getting it
exact isn’t a priority.

Let’s create the `login.html` page in `resources/templates/`. I’ve stripped
out all the styles, SVGs, and unrelated functionality. If you want the complete
code, you can find it on the [GitHub repo](https://github.com/AfeefRazick/spring-authorization-server-guide).

OAuth2 login providers are simple links following the URL format `/oauth2/authorization/{registrationId}`,
while the form login posts to the `/login` endpoint with `username` and
`password` as form data fields.

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome Back! - Ticketed</title>
    <style>
        /* ... all styles */
    </style>
</head>
<body>
<div class="split-container">
    <div class="left-side">
        <div class="logo">Spring Authorization Server</div>
        <div class="hero-text">
            Go from 0-90,<br>
            Your almost at prod!
        </div>
        <img class="mountains" th:src="@{/images/mountains.jpg}" alt="mountains"/>
    </div>
    <div class="right-side">
        <div class="login-container">
            <div class="login-header">
                <h1>Welcome Back!</h1>
                <p>Continue with Google or enter your details.</p>
            </div>
            <a href="/oauth2/authorization/google" role="link" class="google-sign-in">
               Login with Google
            </a>
            <form th:action="@{/login}" method="post">
                <div class="form-group">
                    <label for="username">Email</label>
                    <input
                            type="email"
                            id="username"
                            name="username"
                            placeholder="example@gmail.com"
                            required
                    >
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <div class="password-container">
                        <input
                                type="password"
                                id="password"
                                name="password"
                                placeholder="••••••"
                                required
                        >
                    </div>
                </div>
                <button type="submit" class="login-button">Login</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
```

Now that we have our template, let’s add a controller method to serve
this Thymeleaf template.

```java
// AuthController.java
@Controller
public class AuthController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
```

Previously, we used `Customizer.withDefaults()` when setting up `formLogin`
and `oauth2Login` without any customizations. To make Spring use our custom
login template instead of the default, we need to specify the login page path.
We’ll also allow unauthenticated access to any static resources, such as CSS
and images, that the login page references.

```java
// SecurityConfig.java
@Bean
@Order(2) // security filter chain for the rest of your application and any custom endpoints you may have
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    // @formatter:off
    http
            .cors(Customizer.withDefaults())
            .formLogin(formLogin -> formLogin.loginPage("/login").permitAll()) // Enable form login
            .oauth2Login(oauth2Login -> oauth2Login.loginPage("/login").permitAll()) // Enable oauth2 federated identity login
            .authorizeHttpRequests(authorize ->
                    authorize
                            .requestMatchers("/webjars/**", "/images/**", "/css/**", "/assets/**", "/favicon.ico").permitAll()
                            .anyRequest().authenticated()
            );
    // @formatter:on

    return http.build();
}
```

If we rerun the auth server, we should see the new login page, and both
login methods should work as before.  

To improve the experience, we can handle error states. For example, if invalid
credentials are entered, Spring adds the `error` query parameter to the URL.
We can use this to display an appropriate error message to the user.

```html
<!-- login.html-->
<div th:if="${param.error}" class="alert-error">
    <!-- an svg is here -->
    The combination of email and password is incorrect!
</div>
```

With that, we’ve successfully customized our login page—yep, it’s as easy as that!
