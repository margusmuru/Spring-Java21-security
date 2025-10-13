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
