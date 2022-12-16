package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationEventHandler {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Async
    @EventListener
    public void handleSuccessEvent(AuthenticationSuccessEvent event) {
        try {
            Thread.sleep(5000L);
        } catch (InterruptedException e) {
        }
        Authentication authentication = event.getAuthentication();
        log.info("Successful authentication result: {}", authentication.getPrincipal());
    }

    @EventListener
    public void handleFailureEvent(AbstractAuthenticationFailureEvent event) {
        Exception exception = event.getException();
        Authentication authentication = event.getAuthentication();
        log.warn("Unsuccessful authentication result: {}", authentication.getPrincipal(), exception);
    }
}
