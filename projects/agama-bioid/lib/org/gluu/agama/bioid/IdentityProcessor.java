package org.gluu.agama.bioid;

import io.jans.service.cdi.util.CdiUtil;
import io.jans.as.server.service.AuthenticationService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IdentityProcessor implements IdentityProcessorInterface {

    private static final Logger logger = LoggerFactory.getLogger(IdentityProcessor.class);

    public IdentityProcessor() {
    }

    public boolean authenticate(String username, String password) {
        AuthenticationService authenticationService = CdiUtil.bean(AuthenticationService.class);
        logger.info("Validating {}", username);
        boolean result = authenticationService.authenticate(username, password);
        logger.info("Validation status is {}", result);
        return result;
    }
}
