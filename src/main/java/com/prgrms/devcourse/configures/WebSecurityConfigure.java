package com.prgrms.devcourse.configures;

import com.prgrms.devcourse.jwt.Jwt;
import com.prgrms.devcourse.jwt.JwtAuthenticationFilter;
import com.prgrms.devcourse.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.prgrms.devcourse.oauth2.OAuth2AuthenticationSuccessHandler;
import com.prgrms.devcourse.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

  private final Logger log = LoggerFactory.getLogger(getClass());

  private final JwtConfigure jwtConfigure;

  private final UserService userService;
  public WebSecurityConfigure(JwtConfigure jwtConfigure, UserService userService) {
    this.jwtConfigure = jwtConfigure;
    this.userService = userService;
  }

  @Bean
  public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
    Jwt jwt = getApplicationContext().getBean(Jwt.class);
    return new OAuth2AuthenticationSuccessHandler(jwt, userService);
  }

  @Bean
  public Jwt jwt() {
    return new Jwt(
        jwtConfigure.getIssuer(),
        jwtConfigure.getClientSecret(),
        jwtConfigure.getExpirySeconds()
    );
  }

  @Bean
  public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
    return new HttpCookieOAuth2AuthorizationRequestRepository();
  }

  @Bean
  public OAuth2AuthorizedClientService auth2AuthorizedClientService(
      JdbcOperations jdbcOperations,
      ClientRegistrationRepository clientRegistrationRepository
  ) {
    return new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);
  }

  @Bean
  public OAuth2AuthorizedClientRepository authorizedClientRepository(
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
    return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(oAuth2AuthorizedClientService);
  }

  @Override
  public void configure(WebSecurity web) {
    web.ignoring().antMatchers("/assets/**", "/h2-console/**");
  }


  public JwtAuthenticationFilter jwtAuthenticationFilter() {
    Jwt jwt = getApplicationContext().getBean(Jwt.class);
    return new JwtAuthenticationFilter(jwtConfigure.getHeader(), jwt);
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
      .antMatchers("/api/user/me").hasAnyRole("USER", "ADMIN")
      .anyRequest().permitAll()
      .and()
        //페이지 기반이 아니기 때문에 지워준다.
        .csrf().disable()
        .headers().disable()
        .formLogin().disable()
        .httpBasic().disable()
        .rememberMe().disable()
        .logout().disable()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        //Oauth2 설정
        .oauth2Login()
        .authorizationEndpoint()
        .authorizationRequestRepository(authorizationRequestRepository())
        .and()
        .authorizedClientRepository(getApplicationContext().getBean(AuthenticatedPrincipalOAuth2AuthorizedClientRepository.class))
        .successHandler(oAuth2AuthenticationSuccessHandler())
        .and()
//       예외처리 핸들러
      .exceptionHandling()
      .accessDeniedHandler(accessDeniedHandler())
        .and()
        .addFilterAfter(jwtAuthenticationFilter(), SecurityContextPersistenceFilter.class);

  }

  @Bean
  public AccessDeniedHandler accessDeniedHandler() {
    return (request, response, e) -> {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      Object principal = authentication != null ? authentication.getPrincipal() : null;
      log.warn("{} is denied", principal, e);
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      response.setContentType("text/plain;charset=UTF-8");
      response.getWriter().write("## ACCESS DENIED ##");
      response.getWriter().flush();
      response.getWriter().close();
    };
  }


}