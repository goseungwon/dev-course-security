package com.prgrms.devcourse.configures;

import com.prgrms.devcourse.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

  private final Logger log = LoggerFactory.getLogger(getClass());

  private UserService userService;

  @Autowired
  public void setUserService(UserService userService) {
    this.userService = userService;
  }


  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userService);

//    auth.jdbcAuthentication()
//        .dataSource(dataSource)
//        .usersByUsernameQuery(
//                "SELECT " +
//                        "login_id, passwd, true " +
//                        "FROM " +
//                        "USERS " +
//                        "WHERE " +
//                        "login_id = ?"
//        )
//        .groupAuthoritiesByUsername(
//                "SELECT " +
//                        "u.login_id, g.name, p.name " +
//                        "FROM " +
//                        "users u JOIN groups g ON u.group_id = g.id " +
//                        "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
//                        "JOIN permissions p ON p.id = gp.permission_id " +
//                        "WHERE " +
//                        "u.login_id = ? "
//        )
//        .getUserDetailsService()
//        .setEnableAuthorities(false)
//    ;
  }

//  @Bean
//  @Qualifier("myAsyncTaskExecutor")
//  public ThreadPoolTaskExecutor threadPoolTaskExecutor() {
//    ThreadPoolTaskExecutor threadPoolTaskExecutor = new ThreadPoolTaskExecutor();
//    threadPoolTaskExecutor.setCorePoolSize(3);
//    threadPoolTaskExecutor.setMaxPoolSize(5);
//    threadPoolTaskExecutor.setThreadNamePrefix("my-executor-");
//    return threadPoolTaskExecutor;
//  }

//  @Bean
//  public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(
//          @Qualifier("myAsyncTaskExecutor") AsyncTaskExecutor delegate
//  ) {
//    return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
//  }



  @Override
  public void configure(WebSecurity web) {
    web.ignoring().antMatchers("/assets/**", "/h2-console/**");
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

//  @Override
//  public void configure(AuthenticationManagerBuilder auth) throws Exception {
//    auth.inMemoryAuthentication()
//            .withUser("user")
//            .password("{noop}user123")
//            .roles("USER")
//            .and()
//            .withUser("admin01")
//            .password("{noop}admin123")
//            .roles("ADMIN")
//            .and()
//            .withUser("admin02")
//            .password("{noop}admin123")
//            .roles("ADMIN")
//    ;
//  }

//  @Bean
//  public AccessDecisionManager accessDecisionManager() {
//    List<AccessDecisionVoter<?>> voters = new ArrayList<>();
//    voters.add(new WebExpressionVoter());
//    voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
//    return new UnanimousBased(voters);
//  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
      .antMatchers("/me").hasAnyRole("USER", "ADMIN")
      .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated()")
      .anyRequest().permitAll()
//      .accessDecisionManager(accessDecisionManager())
      .and()
      .formLogin()
      .defaultSuccessUrl("/")
      .permitAll()
      .and()
      .httpBasic()
      .and()
      //쿠키로 자동로그인
      .rememberMe()
      .rememberMeParameter("remember-me")
      .tokenValiditySeconds(300)
      .and()
      //로그아웃 설정
      .logout()
      .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
      .logoutSuccessUrl("/")
      .invalidateHttpSession(true)
      .clearAuthentication(true)
      .and()
      //HTTP를 HTTPS요청으로
      .requiresChannel()
      .anyRequest()
      .requiresSecure()
      .and()

      .sessionManagement()
       .sessionFixation().changeSessionId()
       .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
       .invalidSessionUrl("/")
        .maximumSessions(1)
        .maxSessionsPreventsLogin(false)
         .and()
       .and()
//       예외처리 핸들러
      .exceptionHandling()
      .accessDeniedHandler(accessDeniedHandler())

//                .anonymous()
//                .principal("thisIsAnonymousUser")
//                .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
    ;
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