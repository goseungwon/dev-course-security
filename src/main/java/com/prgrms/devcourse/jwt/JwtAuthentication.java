package com.prgrms.devcourse.jwt;

import com.google.common.base.Preconditions;
import org.apache.commons.lang3.ObjectUtils;

public class JwtAuthentication {

  public final String token;

  public final String username;


  public JwtAuthentication(String token, String username) {
    Preconditions.checkArgument(ObjectUtils.isNotEmpty(token), "token must be provided.");
    Preconditions.checkArgument(ObjectUtils.isNotEmpty(username), "username must be provided.");

    this.token = token;
    this.username = username;
  }

  @Override
  public String toString() {
    return "JwtAuthentication{" +
        "token='" + token + '\'' +
        ", username='" + username + '\'' +
        '}';
  }
}
