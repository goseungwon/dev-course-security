package com.prgrms.devcourse.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Service
public class UserService { //implements UserDetailsService {

  private final UserRepository userRepository;
  private final GroupRepository groupRepository;

  private final Logger log = LoggerFactory.getLogger(getClass());

  public UserService(UserRepository userRepository , GroupRepository groupRepository) {
    this.userRepository = userRepository;
    this.groupRepository = groupRepository;
  }

  @Transactional(readOnly = true)
  public Optional<User> findByUsername(String username) {
    return userRepository.findByUsername(username);
  }

  @Transactional(readOnly = true)
  public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
    checkArgument(isNotEmpty(provider), "provider must be provided");
    checkArgument(isNotEmpty(providerId), "providerId must be provided");

    return userRepository.findByProviderAndProviderId(provider, providerId);
  }

  @Transactional
  public User join(OAuth2User oAuth2User, String provider) {
    checkArgument(oAuth2User != null, "oAuth2User must be provided");
    checkArgument(isNotEmpty(provider), "provider must be provided");

    String providerId = oAuth2User.getName();
    return findByProviderAndProviderId(provider, providerId)
        .map(user -> {
          log.warn("Already exists: {} for provider: {} providerId: {}", user, provider, providerId);
          return user;
        })
        .orElseGet(() -> {
          Map<String, Object> attributes = oAuth2User.getAttributes();
          @SuppressWarnings("unchecked")
          Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
          checkArgument(properties != null, "OAuth2User properties is empty");

          String nickname = (String) properties.get("nickname");
          String profileImage = (String) properties.get("profile_image");
          Group group = groupRepository.findByName("USER_GROUP")
              .orElseThrow(() -> new IllegalStateException("Could not found group for USER_GROUP"));
          return userRepository.save(
              new User(nickname, provider.toString(), providerId, profileImage, group)
          );
        });

    /**
     * username - 카카오 닉네임
     * provider - provider param
     * providerId - oauth2User
     * profileImage - 카카오 인증된 사용자 프로필
     * group - USER_GROUP 사용
     */
  }
}
