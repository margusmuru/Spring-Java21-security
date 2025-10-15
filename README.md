# Introduction
Repository has 3 branches:
- basic-auth - basic username+password auth
- jwt-auth - basic authentication using JWT token
- main - JWT auth but with refresh-tokens, logout and Redis for key blacklists.

This is a very barebones example of how to implement Spring Security with JWT and refresh tokens. There are no proper dto/model/entity classes, no proper exception handling (a simple RuntimeException is thrown). In a production application, entities should have proper ID values properly generated. Database should have proper foreign keys etc. Code structure is also very simple and should be improved for production use.

# Table of contents
- [Spring security dependency and default login](#spring-security-dependency-and-default-login)
- [CSRF](#csrf)
- [Configure Spring Web Security](#configure-spring-web-security)
- [JWT](#jwt)
- [Verify scenarios](#verify-scenarios)

# Spring security dependency and default login
To use Spring Security, you must add dependency
```
org.springframework.boot:spring-boot-starter-security
```
This will secure all endpoints by defult and provide a default login form under `/login`
## Login
Username
```
user
```
Password is provided in logs
```
Using generated security password: 2b24222c-ff5b-4530-bbb4-e43fba96a90c
```
By logging in a cookie is added to the browser and requested endpoint can be reached.
To login in **Postman**, add Authorization -> Basic auth to your request and provide correct username and password.
## Logout
Go to
```
localhost:8080/logout
```
## Change default user and password
Add properties to `application.properties`
```
spring.security.user.name=user
spring.security.user.password=password
```
___

# Spring security filters
Spring Security filters are a **core part of the Spring Security framework**. They are implemented as a chain of `javax.servlet.Filter` objects that sit in front of your application’s endpoints (controllers, APIs, static resources, etc.) and intercept every HTTP request/response to apply security logic.

- **Servlet filters**: Each filter processes the request and can decide whether to pass it along, modify it, or block it.
- **Security enforcement**: They handle things like authentication, authorization, session management, CSRF protection, and request logging.
- **Ordered chain**: Filters are arranged in a chain (called the _filter chain_). The order is crucial because, for example, authentication must happen before authorization.

Spring security has about 30 filters. Not all of them are active by default.
More common ones:
- **`SecurityContextPersistenceFilter`**: Restores the `SecurityContext` (holds authentication data) for the current request.
- **`UsernamePasswordAuthenticationFilter`**: Handles login form submission, checking username/password against authentication providers.
- **`BasicAuthenticationFilter`**: Supports HTTP Basic authentication (username and password sent in headers).
- **`BearerTokenAuthenticationFilter`**: Supports JWT or OAuth2 bearer tokens.
- **`ExceptionTranslationFilter`**: Catches security exceptions (like `AccessDeniedException`) and handles them gracefully.
- **`FilterSecurityInterceptor`**: The last line of defense—makes the authorization decision (whether the request is allowed to access the resource).
___

# CSRF
*Cross Site Request Forgery*
CSRF is a type of **web security vulnerability** where an attacker tricks a victim’s browser into sending unauthorized requests to a trusted website where the victim is already authenticated.
- In simpler terms: The attacker abuses the fact that your browser automatically includes your cookies (session, auth tokens, etc.) when making requests to a site you’re logged into.
- This allows the attacker to perform actions **on your behalf** without your consent.

By default, Spring Security will take care of CSRF and add validation for it. Without including the token with your request POST, PUT, DELETE requests will throw 401 error.

## Add CSRF token
Add header
```
X-CSRF-TOKEN
```
Get token value from HttpServletRequest
>[!warning] This is for demo purposes. Do not do this in production
```java
import org.springframework.security.web.csrf.CsrfToken;

@GetMapping("/csrf-token")  
public CsrfToken getCsrfToken(HttpServletRequest request) {  
  return (CsrfToken) request.getAttribute("_csrf");  
}
```
Example response:
```json
{
	"token": "f6mPcFWooDU4u6VHHGSAsknsQUgQpZFYVx6d-V5rXGx_3YOUSMq-SGWclFAVjJckeEm003rabCkplqF1bieqyGlZbAlNvuKh",
	"headerName": "X-CSRF-TOKEN",
	"parameterName": "_csrf"
}
```
___

# Configure Spring Web Security
Add configuration class
```java
@Configuration  
@EnableWebSecurity  
public class SecurityConfig {  
  
}
```
**@Configuration** tells Spring to look for configurations in this class
**@EnableWebSecurity** tells Spring to not use default security config and use the one provided in this class.

## Config Required Beans
This is the basic bean for SecurityFilterChain. As there is no configuration made and only `build()`called, Spring Security is not applied and you can login without credentials.
```java
@Bean  
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {  
  return http.build();  
}
```
>[!warning] Make sure you do not use name *springSecurityFilterChain* as it will be in a conflict with a bean implemented by Spring Framework itself

### Disable CSRF
This is for demo purposes only!
```java
.csrf(customizer -> customizer.disable()) 
// .csrf(AbstractHttpConfigurer::disable)
```

### Authenticate requests
This adds authorization but does not enable `/login`form redirect. You are also unable to authenticate with Basic Auth in **Postman**
```java
.authorizeHttpRequests(request -> request.anyRequest().authenticated())
```
### Form login
```java
.formLogin(Customizer.withDefaults())
```
### Basic http
For **Postman** to work and not return form login page from a REST controller, add:
```java
.httpBasic(Customizer.withDefaults())
```
### Session creation policy
Configure sessions to be **STATELESS**
>[!warning] This will effectively disable login form as there will be no sessions and you must authenticate for each request.
>This will no disable Basic Auth authorization in **Postman**
```java
.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
```
If you disable form login as well, you will get browser authentication popup on every request.

### UserDetailsService
UserDetailsService is an interface. You can create your own or use one of prebuilt variants.
For example:
```java
@Bean  
public UserDetailsService userDetailsService() {  
  return new InMemoryUserDetailsManager();  
}
```
Add dummy user to in-memory database
>[!error] Do not use this in production. Ever.
```java
@Bean  
public UserDetailsService userDetailsService() {  
  UserDetails user1 = User.withDefaultPasswordEncoder()  
      .username("user")  
      .password("password")  
      .roles("USER")  
      .build();  
  return new InMemoryUserDetailsManager(user1);  
}
```
Or implement one with a proper database. There is readme in `/etc`directory for postgreSQL Do not forget to add spring datasource properties to `application.properties`
```java
@Component  
@RequiredArgsConstructor  
public class MyUserDetailsService implements UserDetailsService {  
    private final UserRepository userRepository;  
  
    @Override  
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {  
        Users user = userRepository.findByUsername(username)  
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));  
  
        return new UserPrincipal(user);  
    }}
```

### AuthenticationProvider
>[!info] instead of UserDetailsService bean, implement AuthenticationProvider
```java
@Bean  
public AuthenticationProvider authenticationProvider() {  
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();  
    provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());  
    provider.setUserDetailsService(userDetailsService);  
    return provider;  
}
```
Basic bean that would tell Spring to use no password encoder (Deprecated due to insecurity) and userDetailsService that would fetch UserDetails from db.
>[!info] for postgreSQL implementation, refer git repository.

>[!info] At this point basic auth should be working. Refer repository branch `basic-auth`

___

## BCrypt
Bcrypt is a password-hashing function designed with security as its primary focus. Its key features include:

- **Adaptive Hashing:** Bcrypt is intentionally slow, and its computational cost can be increased over time. This "work factor" can be tuned to keep pace with advancements in hardware, making brute-force attacks increasingly difficult and expensive for attackers. Spring Security's BCryptPasswordEncoder allows for the configuration of this strength parameter.

- **Salting:** To combat rainbow table attacks, bcrypt automatically incorporates a salt—a random string of data—into the hashing process. This ensures that even identical passwords will have unique hash values, preventing attackers from using pre-computed hash tables to crack passwords. Spring Security's BCryptPasswordEncoder handles the generation and inclusion of this salt automatically.
### Users controller and service
Refere to git repository. We need to implement
- UserController
- UserService
- Add basic endpoint and service method to register new user.
```java
@RestController  
@RequiredArgsConstructor  
public class UserController {  
    private final UserService userService;  
  
    @PostMapping("/register")  
    public Users register(@RequestBody Users user){  
        return userService.registerUser(user);  
    }  
}
```
```java
@Service  
@RequiredArgsConstructor  
public class UserService {  
    private final UserRepository userRepository;  
  
    public Users registerUser(Users user) {  
        return userRepository.save(user);  
    }
}
```

### Add BCrypt encoder to userService
Encrypt password when registering a new user. All new passwords will now be encoded. Strength is set to 12.
```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;  
import org.springframework.stereotype.Service;  
  
@Service  
@RequiredArgsConstructor  
public class UserService {  
    private final UserRepository userRepository;  
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);  
  
    public Users registerUser(Users user) {  
        user.setPassword(encoder.encode(user.getPassword()));  
        return userRepository.save(user);  
    }
}
```

### Add BCrypt encoder to authentication provider
When checking for user password match, the password will be encrypted and then compared to the one in database.
```java
provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
```

>[!info] At this point basic auth should be working. Refer repository branch `basic-auth`

___


# JWT
A JSON Web Token (JWT), often pronounced "jot," is a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs are an open standard (RFC 7519) and are commonly used for authentication and information exchange in modern web applications and APIs.

## Structure of a JWT

A JWT consists of three parts separated by periods (.): the Header, the Payload, and the Signature.

- **Header**: The header typically consists of two parts: the type of the token, which is JWT, and the signing algorithm being used, such as HMAC SHA256 or RSA. This JSON is then Base64Url encoded to form the first part of the JWT.
- **Payload**: The payload contains the claims.Claims are statements about an entity (typically, the user) and additional data. There are three types of claims:
    - **Registered claims**: These are a set of predefined claims which are not mandatory but recommended to provide a set of useful, interoperable claims. Some examples are iss (issuer), exp (expiration time), and sub (subject).
    - **Public claims**: These are claims that are defined by those using JWTs. To avoid collisions, they should be defined in the IANA JSON Web Token Registry or be a URI that contains a collision-resistant namespace.
    - **Private claims**: These are the custom claims created to share information between parties that agree on using them.
      The payload is also Base64Url encoded to form the second part of the JWT.
- **Signature**: To create the signature portion, you take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign it. The signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.

## Implementation
Lets implement JWT to our application.
### Add dependencies.
JWT is not a part of Spring Framework so first add dependencies
```kotlin
implementation("io.jsonwebtoken:jjwt-api:0.12.6")  
runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")  
runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")
```
### Modify securityFilterChain
Allow `/register` and `/login`endpoints to to have no auth. Remove default auth  as well.
>[!warning] Leaving default auth can cause issues.
>Even if /register endpoint is allowed, default auth will check for username and password. As there are no such headers provided, 401 is returned even if that endpoing has permitAll()
```java
@Bean  
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {  
    return http  
            .csrf(AbstractHttpConfigurer::disable)  
            .authorizeHttpRequests(request -> request  
                    .requestMatchers("/login","/register").permitAll()  
                    .anyRequest().authenticated())  
            .sessionManagement(session -> session  
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS))  
            .build();  
}
```

### Create AuthenticationManager bean
```java
@Bean  
public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {  
    return config.getAuthenticationManager();  
}
```

### Create login endpoint
```java
@PostMapping("/login")  
public String login(@RequestBody Users user){  
    return userService.verify(user);  
}
```

### Verify login
This is for demo purposes. In `UserService`:
```java
public String verify(Users user) {  
    Authentication authentication = authenticationManager  
            .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));  
    if (authentication.isAuthenticated()) {  
        return "User verified";  
    }    return "User not verified";  
}
```
If provided username and password are correct, "User verified" is returned.
After demo, replase success message with
```java
return jwtService.generateToken(user.getUsername());
```

### JwtService
```java
@Service  
public class JwtService {  
    // must be at least 256 bits for HS256  
    // generate secret: https://generate-random.org/encryption-keys  
    // validate generated token: https://www.jwt.io/  
    private final String SECRET_KEY = "ba0a6bcb9c5c194f7a834d47579e6f85eeb0dbb3fcb4d0cec79ad7a320f5e3d0";  
  
    public String generateToken(String username) {  
  
        Map<String, Object> claims = new HashMap<>();  
  
        return Jwts.builder()  
                .claims()  
                .add(claims)  
                .subject(username)  
                .issuedAt(new Date(System.currentTimeMillis()))  
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 30))  
                .and()  
                .signWith(getKey())  
                .compact();  
  
    }  
    private Key getKey() {  
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);  
        return Keys.hmacShaKeyFor(keyBytes);  
    }}
```
1. **Map<String, Object> claims = new HashMap<>();**: This line initializes an empty HashMap. In the context of JWTs, "claims" are pieces of information asserted about a subject. They are key-value pairs that make up the payload of the JWT. While this specific map is empty, it's set up to allow for the addition of custom claims, such as user roles or permissions.
2. **Jwts.builder()**: This is the starting point of building the JWT. The JJWT library utilizes a fluent builder pattern, which allows for the chaining of method calls in a readable and convenient way.
3. **.claims()**: This method returns a ClaimsMutator instance, which is essentially an object that allows for the manipulation of the JWT's claims.
4. **.add(claims)**: The add method takes the claims map created in the first step and adds all its key-value pairs to the JWT's payload. Even though the map is empty in this example, this is where you would pass in any custom data you want to include in the token.
5. **.subject(username)**: This sets the "sub" (subject) claim of the JWT. The subject claim identifies the principal that is the subject of the JWT. In this case, it's the username.
6. **.issuedAt(new Date(System.currentTimeMillis()))**: This sets the "iat" (issued at) claim. This claim identifies the time at which the JWT was issued. It's set to the current system time.
7. **.expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 30))**: This sets the "exp" (expiration time) claim. This claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. The time is calculated as the current time plus 30 hours (1000 milliseconds * 60 seconds * 60 minutes * 30 hours).
8. **.and()**: This method is part of the JJWT fluent interface and returns the JwtBuilder instance. This allows you to continue building the token after you have finished modifying the claims.
9. **.signWith(getKey())**: This is a crucial security step. The signWith method signs the constructed JWT with a secret key. This signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way. The getKey() method is responsible for providing the secret key used for the signature. This key should be kept secure on the server.
10. **.compact()**: This final method in the chain takes all the configured parts of the JWT (header, payload, and signature), serializes them into a compact, URL-safe string. This resulting string is the JWT.

### Add JWT filter to security config
Add component:
```java
private final JwtFilter jwtFilter;
```
To the end of chain:
```java
.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
```
Add filter itself. It will extract token from headers, get username, validate token and add AuthorizationToken to Spring Security Context.
```java
import jakarta.servlet.FilterChain;  
import jakarta.servlet.ServletException;  
import jakarta.servlet.http.HttpServletRequest;  
import jakarta.servlet.http.HttpServletResponse;  
import lombok.RequiredArgsConstructor;  
import org.springframework.context.ApplicationContext;  
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;  
import org.springframework.security.core.context.SecurityContextHolder;  
import org.springframework.security.core.userdetails.UserDetails;  
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;  
import org.springframework.stereotype.Component;  
import org.springframework.web.filter.OncePerRequestFilter;  
  
import java.io.IOException;  
  
@Component  
@RequiredArgsConstructor  
public class JwtFilter extends OncePerRequestFilter {  
    private final JwtService jwtService;  
    private final ApplicationContext context;  
  
    @Override  
    protected void doFilterInternal(HttpServletRequest request,  
                                    HttpServletResponse response,  
                                    FilterChain filterChain) throws ServletException, IOException {  
        String authHeader = request.getHeader("Authorization");  
        String token = null;  
        String username = null;  
  
        if (authHeader != null && authHeader.startsWith("Bearer ")) {  
            token = authHeader.substring(7);  
            username = jwtService.extractUsername(token);  
        }  
        // if username is not null and user is not already authenticated  
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {  
            UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(username);  
            // validate token  
            if (jwtService.validateToken(token, userDetails)) {  
                UsernamePasswordAuthenticationToken authToken =  
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());  
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));  
                // add authentication to security context  
                SecurityContextHolder.getContext().setAuthentication(authToken);  
            }        }        filterChain.doFilter(request, response);  
    }
}
```
Update JwtService with methods. These will validate token and extract username.
```java
public String extractUsername(String token) {  
    return extractClaim(token, Claims::getSubject);  
}  
  
public boolean validateToken(String token, UserDetails userDetails) {  
    final String userName = extractUsername(token);  
    return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));  
}  
  
private boolean isTokenExpired(String token) {  
    return extractClaim(token, Claims::getExpiration).before(new Date());  
}  
  
private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {  
    final Claims claims = extractAllClaims(token);  
    return claimResolver.apply(claims);  
}  
  
private Claims extractAllClaims(String token) {  
    return Jwts.parser()  
            .verifyWith(getKey())  
            .build()  
            .parseSignedClaims(token)  
            .getPayload();  
}
```
>[!info] Check repository branch `jwt-auth`.
>Login method should return a token and you should be able to access authenticated endpoints.

# JWT with refresh tokens
In a simple authentication model, a user logs in, and the server issues a short-lived JWT. This token is then sent with each subsequent request to protected resources. The backend's only responsibility is to validate the token's signature and expiration. If the signature is valid and the token hasn't expired, the user is considered authenticated. In this scenario, there is no need to store the token on the server, which offers the key benefits of scalability and reduced database load.

## When to Consider Server-Side Storage

Several critical functionalities necessitate some form of server-side storage related to active tokens:

- **Token Revocation:** If a user logs out, changes their password, or an administrator needs to terminate a session, the backend must have a way to invalidate the corresponding JWT. Since JWTs are valid until they expire, a simple client-side deletion isn't enough. A compromised token could still be used until its expiration. To address this, a "denylist" or "blacklist" of revoked tokens can be maintained on the server. Before validating a token, the backend checks if it's on this list.
- **Refresh Token Management:** To provide a seamless user experience without requiring frequent log-ins, applications often use a combination of short-lived access tokens and long-lived refresh tokens. When an access token expires, the client can use the refresh token to obtain a new one. The backend must securely store and manage these refresh tokens, associating them with the user. This storage is essential for validating refresh token requests and revoking them if necessary.
- **Detecting Compromised Tokens:** Storing metadata about issued tokens can help in identifying suspicious activity. For instance, if a refresh token is used after it has been reported as stolen, the backend can invalidate it and all associated access tokens.
- **Session Management and Concurrent Login Control:** A backend might need to track active sessions for a user to enforce limits on concurrent logins or to provide users with a view of their active sessions. This requires storing information about the issued tokens.

## Best Practices for Backend JWT Management
Regardless of the storage strategy, several best practices should be followed:
- **Keep Access Tokens Stateless:** The primary access token should remain stateless on the backend to leverage the core benefits of JWTs.
- **Secure Refresh Tokens:** Refresh tokens are powerful credentials and must be stored securely. They should have a long but finite lifespan and be revocable.
- **Use a Denylist for Revocation:** For immediate token revocation, maintaining a denylist in a fast-access data store like Redis is a common and effective pattern.
- **Consider Token Metadata:** Storing metadata about when and from where tokens were issued can be valuable for security auditing and anomaly detection.

### The Core Concept: Access vs. Refresh Tokens

At its heart, the refresh token mechanism involves two types of tokens:

- **Access Token:** This token is short-lived (e.g., 15-30 minutes) and is sent with every request to access protected resources. Its short lifespan minimizes the damage if it's compromised
- **Refresh Token:** This is a longer-lived token (e.g., days or weeks) that is used to obtain a new access token when the old one expires. It is sent to a specific endpoint on the authorization server to get a new pair of access and refresh tokens.

## The Implementation Flow
Here's a step-by-step breakdown of how to implement the refresh token flow:

### 1. Initial Authentication & Token Issuance
- The user provides their credentials (e.g., username and password) to your application.
- Your authentication server validates these credentials.
- Upon successful authentication, the server generates both an access token and a refresh token.
- These tokens are then sent back to the client application.

#### 2. Storing Tokens on the Client
Securely storing tokens on the client-side is critical:
- **Access Token:** This can be stored in memory (e.g., in a JavaScript variable). Storing it in localStorage or sessionStorage is generally discouraged as it's vulnerable to cross-site scripting (XSS) attacks.
- **Refresh Token:** This should be stored in a more secure manner. A common best practice for web applications is to store the refresh token in an HttpOnly cookie. This makes it inaccessible to JavaScript, mitigating XSS risks.

#### 3. Accessing Protected Resources
- The client application includes the access token in the Authorization header (typically as a Bearer token) of every request to your API's protected endpoints.
- The server validates the access token's signature and expiration. If valid, it processes the request.

#### 4. Handling Expired Access Tokens
- When the access token expires, the API will return an error (e.g., a 401 Unauthorized status).
- The client application should be designed to intercept this error.

#### 5. Refreshing the Access Token
- Upon receiving a 401 error, the client sends a request to a dedicated token refresh endpoint (e.g., /api/refresh-token).
- This request includes the refresh token.
- The server receives the refresh token and performs the following checks:
    - **Is it valid and not expired?**
    - **Is it present in a database of active refresh tokens?** This is crucial for being able to revoke tokens.
    - **Has it been revoked?** (Checking against a denylist or "blacklist" of revoked tokens).
#### 6. Issuing New Tokens
- If the refresh token is valid, the server generates a **new** access token and, importantly, a **new** refresh token. This is known as **refresh token rotation**.
- The old refresh token is invalidated.
- The new token pair is sent back to the client.
- The client then updates its stored tokens and retries the original failed API request with the new access token.

### Why is Refresh Token Rotation Important?
Refresh token rotation is a key security measure. If a refresh token is ever compromised and used by an attacker, the legitimate user's application will also attempt to use it. When the attacker uses the token, a new one is issued, and the old one is invalidated. If the legitimate user's application then tries to use the now-invalidated token, the server can detect this reuse. This "reuse detection" can be a signal of a security breach, allowing the server to invalidate all tokens for that user and force them to log in again.

### Server-Side Considerations
To implement this securely on the backend:
- **Store Refresh Tokens Securely:** You must store a reference to the issued refresh tokens in a database. This allows you to verify their validity and to revoke them if needed. You should at least store a hashed version of the token, the user it belongs to, and its expiry date.
- **Have a Token Revocation Mechanism:** You need the ability to invalidate a user's refresh tokens, for instance, when they change their password or log out from a specific device. This is often done by deleting the token from your database or adding it to a revocation list.
- **Use HTTPS:** Always transmit tokens over a secure HTTPS connection to prevent them from being intercepted.

### The Role of Redis: The High-Speed Blacklist
Redis is an in-memory data store, which makes it incredibly fast for read and write operations. It's the perfect tool for managing a blacklist of invalidated tokens.

**Here’s the recommended architecture and flow:**

1. **On User Logout:** When a user hits the /logout endpoint, you don't "delete" the JWT (since it lives on the client). Instead, you add the token to a blacklist in Redis.
2. **Set a TTL (Time-to-Live):** To prevent Redis from filling up with expired tokens, you store the token in the blacklist with an expiration time that matches the token's original remaining validity. For example, if a token has 10 minutes left before it expires, you add it to Redis with a TTL of 10 minutes. Redis will automatically evict the key after that time.
3. **Check on Every Request:** Your Spring Security filter, before validating the token's signature, first performs a quick check against Redis.
    - If the token is found in the Redis blacklist, the request is immediately rejected (e.g., with a 401 Unauthorized error), even if the token's signature and expiration are technically valid.
    - If the token is not in Redis, the filter proceeds with the standard cryptographic validation.

### The Role of PostgreSQL: The Persistent Source of Truth

PostgreSQL is your relational database and serves as the permanent, reliable source of truth for data that must not be lost. Its role in the authentication process is different from Redis's.

**Use PostgreSQL for:**

- **User Credentials:** Storing user information like usernames, hashed passwords, and roles. Your UserDetailsService in Spring Security will load data from here to authenticate users and create tokens in the first place.
- **Refresh Tokens (Optional but Recommended):** While access tokens are short-lived, you often use long-lived refresh tokens to allow users to get a new access token without logging in again. These refresh tokens **should be stored persistently**, and PostgreSQL is a suitable place for them. You would store the refresh token (or a hashed version of it), its expiry date, and the user it belongs to.

## Implement Redis
For a fast key-value storage, lets use Redis
### Docker compose
Refer repository `/etc/redis` for `docker-compose.yml`
### Add Spring dependency
```kotlin
implementation("org.springframework.boot:spring-boot-starter-data-redis")
```
### Add properties
```properties
spring.data.redis.host=localhost  
spring.data.redis.port=6379  
spring.data.redis.password=mypassword
```
### Java classes
>[!info] Refer to repository

Add classes:
#### KvController
```java
import com.margusmuru.demo.service.RedisKvService;  
import lombok.RequiredArgsConstructor;  
import org.springframework.http.ResponseEntity;  
import org.springframework.web.bind.annotation.DeleteMapping;  
import org.springframework.web.bind.annotation.GetMapping;  
import org.springframework.web.bind.annotation.PathVariable;  
import org.springframework.web.bind.annotation.PutMapping;  
import org.springframework.web.bind.annotation.RequestBody;  
import org.springframework.web.bind.annotation.RequestMapping;  
import org.springframework.web.bind.annotation.RequestMethod;  
import org.springframework.web.bind.annotation.RequestParam;  
import org.springframework.web.bind.annotation.RestController;  
  
import java.time.Duration;  
import java.util.Map;  
  
@RestController  
@RequestMapping("/kv")  
@RequiredArgsConstructor  
public class KvController {  
  
    private final RedisKvService service;  
  
    @PutMapping("/{key}")  
    public ResponseEntity<Void> put(@PathVariable String key,  
                                    @RequestParam(required = false) Long ttlSeconds,  
                                    @RequestBody String value  
    ) {  
        if (ttlSeconds != null) {  
            service.set(key, value, Duration.ofSeconds(ttlSeconds));  
        } else {  
            service.set(key, value);  
        }        return ResponseEntity.noContent().build();  
    }  
    @GetMapping("/{key}")  
    public ResponseEntity<?> get(@PathVariable String key) {  
        String val = service.get(key);  
        return (val == null) ? ResponseEntity.notFound().build()  
                : ResponseEntity.ok(Map.of("key", key, "value", val));  
    }  
    @DeleteMapping("/{key}")  
    public ResponseEntity<?> delete(@PathVariable String key) {  
        boolean deleted = Boolean.TRUE.equals(service.delete(key));  
        return deleted ? ResponseEntity.noContent().build()  
                : ResponseEntity.notFound().build();  
    }  
    @RequestMapping(value = "/{key}", method = RequestMethod.HEAD)  
    public ResponseEntity<Void> exists(@PathVariable String key) {  
        return Boolean.TRUE.equals(service.exists(key))  
                ? ResponseEntity.ok().build()  
                : ResponseEntity.notFound().build();  
    }}
```

#### RedisKvService
```java
import lombok.RequiredArgsConstructor;  
import org.springframework.data.redis.core.StringRedisTemplate;  
import org.springframework.data.redis.core.ValueOperations;  
import org.springframework.stereotype.Service;  
  
import java.time.Duration;  
  
@Service  
@RequiredArgsConstructor  
public class RedisKvService {  
  
    private final StringRedisTemplate redis;  
  
    public void set(String key, String value) {  
        redis.opsForValue().set(key, value);  
    }  
    public void set(String key, String value, Duration ttl) {  
        ValueOperations<String, String> ops = redis.opsForValue();  
        ops.set(key, value, ttl);  
    }  
    public String get(String key) {  
        return redis.opsForValue().get(key);  
    }  
    public Boolean delete(String key) {  
        return redis.delete(key);  
    }  
    public Boolean exists(String key) {  
        return redis.hasKey(key);  
    }
}
```

### Kv endpoint security
For demo purposes add `/kv/**` to `permitAll()` endpoints list

### Test redis
Example KvController allows to play around with redis. Add, query and delete entries, play around with ttl (time-to-live) values.
```bash
# set
curl -X PUT "http://localhost:8080/kv/hello" \
     -H "Content-Type: text/plain" \
     --data "world"

# set with TTL (60s)
curl -X PUT "http://localhost:8080/kv/temp?ttlSeconds=60" \
     -H "Content-Type: text/plain" \
     --data "I expire soon"

# get
curl http://localhost:8080/kv/hello
# → {"key":"hello","value":"world"}

# check existence
curl -I http://localhost:8080/kv/hello  # 200 OK if exists

# delete
curl -X DELETE http://localhost:8080/kv/hello
```

## Implement refresh token logic
I am not gonna copy-paste code here, you can look at code in the repository yourself. I will explain concepts.
### Add refresh_token table
Check readme in `/etc/postgresql`. I added a new table for refresh-tokens. A new token is generated and saved along with JWT token.
While JWT is not saved, refresh-token gets hashed and saved to refresh_token table.
When JWT expires and refresh-token is not expired (they should have long expire date but for demo purposes I set it to 1 hour) it can be used to get a new JWT token later.
Check `com.margusmuru.demo.service.UserService#verify` method.
- `JwtService`is used to generate a new refresh-token
- `RefreshTokenService` is used to save it.
  Login endpoint now returns something like this:
```json
{
	"token": "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJ3IiwiaWF0IjoxNzYwNDc2MzI4LCJleHAiOjE3NjA0NzY5Mjh9.XRuz7b1MANaDOfW0eFzcjKg_PA74h49l2PejCp1IhlDKyPLniNbLxHAHVcMVhPDj",
	"refreshToken": "031629e3-733b-43b6-b061-8add7b3a9036w"
}
```

## refresh-token endpoint
UserController now has an endpoint `/refresh-token`. Once user has logged in, it can send a request with refresh-token. If token is valid, a new set of tokens is generated. If a non-expired JWT token is present in headers, it will be invalidated as well.
This endpoint is also added to security config `permitAll()`list as it can and most likely is called without having a valid JWT token.
>[!warning] This also highlights why it is very important to keep refresh-token secure. A new set of keys is generated for an user just using a valid refresh-token. It cannot be validated if user who sent the request with existing tokens really is the person it claims to be.

There is a missing logic where expired refresh-tokens are never deleted so there should be a cron job or postgresql cron job that would remove such tokens.

## JwtFilter update
Jwt filter was updated with
```java
!redisKvService.exists("blacklist:" + token
```
If JWT token is valid, final step is to verify it is not blacklisted in Redis. If not, user is authenticated.

## logout endpoint
UserController now has an endpoint `/logout` that logs out the user. What happens:
- JWT token is invalidated by adding it to the blacklist in Redis
- refresh-token is invalidated by deleting it from the database.
>[!warning] add config to change spring security default endpoint
>Otherwise it will be in conflict with our endpoint.

```java
.logout(logout -> logout
        .logoutUrl("/perform_logout"))
```
Or
  ```java
  logout(AbstractHttpConfigurer::disable)
  ```


## Conclusion
Thats it, authentication works.

# Verify scenarios
Here are some scenarios to validate logic.
## User logs in and can access `/students`endpoint
- /login
- /students
- success
## User is not logged in and cannot access `/students`endpoint
- invalid/missing JWT token in headers
- /students
- 403 error
## User logs in, calls `/refresh-token`, old tokens do not work
- /login
- /refresh-tokens
- *using old JWT token in headers* /students
- 403 error
- *using old refresh-token* /refresh-token
- error
## User logs in, logs out, `/students` returns error
- /login
- /logout
- success
- /students
- error
## User logs in, logs out, `/refresh-token` returns error
- /login
- /logout
- success
- /refresh-token
- error