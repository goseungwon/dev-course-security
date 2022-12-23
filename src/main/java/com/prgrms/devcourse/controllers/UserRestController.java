package com.prgrms.devcourse.controllers;

import com.prgrms.devcourse.jwt.Jwt;
import com.prgrms.devcourse.jwt.JwtAuthentication;
import com.prgrms.devcourse.jwt.JwtAuthenticationToken;
import com.prgrms.devcourse.user.LoginRequest;
import com.prgrms.devcourse.user.User;
import com.prgrms.devcourse.user.UserDto;
import com.prgrms.devcourse.user.UserService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserRestController {

//  private final Jwt jwt;

  private final UserService userService;

  private final AuthenticationManager authenticationManager;

  public UserRestController(UserService userService, AuthenticationManager authenticationManager) {
    this.userService = userService;
    this.authenticationManager = authenticationManager;
  }

  @PostMapping("/user/login")
  public UserDto login(@RequestBody LoginRequest request) {
    JwtAuthenticationToken authToken = new JwtAuthenticationToken(request.getPrincipal(), request.getCredentials());
    Authentication resultToken = authenticationManager.authenticate(authToken);
    JwtAuthenticationToken authenticated = (JwtAuthenticationToken) resultToken;
    JwtAuthentication authentication = (JwtAuthentication) authenticated.getPrincipal();
    User user = (User) authenticated.getDetails();
    return new UserDto(authentication.token, authentication.username, user.getGroup().getName());
  }

  @GetMapping(path = "/user/me")
  public UserDto me(@AuthenticationPrincipal JwtAuthentication jwtAuthentication) {
    return userService.findByLoginId(jwtAuthentication.username)
        .map(user ->
            new UserDto(jwtAuthentication.token, jwtAuthentication.username, user.getGroup().getName())
            )
        .orElseThrow(() -> new IllegalArgumentException("Could not found user for " + jwtAuthentication.username));
  }

  /**
   * 주어진 사용자의 JWT 토큰을 출력함
   * @param username 사용자명
   * @return JWT 토큰
   */
//  @GetMapping(path = "/user/{username}/token")
//  public String getToken(@PathVariable String username) {
//    UserDetails userDetails = userService.loadUserByUsername(username);
//    String[] roles = userDetails.getAuthorities().stream()
//        .map(GrantedAuthority::getAuthority)
//        .toArray(String[]::new);
//    return jwt.sign(Jwt.Claims.from(userDetails.getUsername(), roles));
//  }
//
//  /**
//   * 주어진 JWT 토큰 디코딩 결과를 출력함
//   * @param token JWT 토큰
//   * @return JWT 디코드 결과
//   */
//  @GetMapping(path = "/user/token/verify")
//  public Map<String, Object> verify(@RequestHeader("token") String token) {
//    return jwt.verify(token).asMap();
//  }

}
