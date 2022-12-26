package com.prgrms.devcourse.controllers;

import com.prgrms.devcourse.jwt.JwtAuthentication;
import com.prgrms.devcourse.user.UserDto;
import com.prgrms.devcourse.user.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserRestController {

//  private final Jwt jwt;

  private final UserService userService;

  public UserRestController(UserService userService) {
    this.userService = userService;
  }

  /*private final AuthenticationManager authenticationManager;

  public UserRestController(UserService userService, AuthenticationManager authenticationManager) {
    this.userService = userService;
    this.authenticationManager = authenticationManager;
  }*/

/*  @PostMapping("/user/login")
  public UserDto login(@RequestBody LoginRequest request) {
    JwtAuthenticationToken authToken = new JwtAuthenticationToken(request.getPrincipal(), request.getCredentials());
    Authentication resultToken = authenticationManager.authenticate(authToken);
    JwtAuthenticationToken authenticated = (JwtAuthenticationToken) resultToken;
    JwtAuthentication authentication = (JwtAuthentication) authenticated.getPrincipal();
    User user = (User) authenticated.getDetails();
    return new UserDto(authentication.token, authentication.username, user.getGroup().getName());
  }*/

  @GetMapping(path = "/user/me")
  public UserDto me(@AuthenticationPrincipal JwtAuthentication jwtAuthentication) {
    return userService.findByUsername(jwtAuthentication.username)
        .map(user ->
            new UserDto(jwtAuthentication.token, jwtAuthentication.username, user.getGroup().getName())
            )
        .orElseThrow(() -> new IllegalArgumentException("Could not found user for " + jwtAuthentication.username));
  }



}
