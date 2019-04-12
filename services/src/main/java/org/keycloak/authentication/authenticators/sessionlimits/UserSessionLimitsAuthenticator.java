package org.keycloak.authentication.authenticators.sessionlimits;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class UserSessionLimitsAuthenticator extends AbstractSessionLimitsAuthenticator {
    private static Logger logger = Logger.getLogger(UserSessionLimitsAuthenticator.class);

    String behavior;

    public UserSessionLimitsAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        Map<String, String> config = authenticatorConfig.getConfig();

        // Get the configuration for this authenticator
        behavior = config.get(UserSessionLimitsAuthenticatorFactory.BEHAVIOR);
        int userRealmLimit = getIntConfigProperty(UserSessionLimitsAuthenticatorFactory.USER_REALM_LIMIT, config);
        int userClientLimit = getIntConfigProperty(UserSessionLimitsAuthenticatorFactory.USER_CLIENT_LIMIT, config);

        // Get the session count in this realm for this specific user
        List<UserSessionModel> userSessionsForRealm = session.sessions().getUserSessions(context.getRealm(), context.getUser());
        int userSessionCountForRealm = userSessionsForRealm.size();

        // Get the session count related to the current client for this user
        ClientModel currentClient = context.getAuthenticationSession().getClient();
        logger.infof("Client: %s", currentClient.getClientId());

        List<UserSessionModel> userSessionsForClient = userSessionsForRealm.stream().filter(session -> session.getAuthenticatedClientSessionByClient(currentClient.getId()) != null).collect(Collectors.toList());
        int userSessionCountForClient = userSessionsForClient.size();

        logger.infof("realm limit: %s", userRealmLimit);
        logger.infof("client limit: %s", userClientLimit);
        logger.infof("session-realm-count: %s", userSessionCountForRealm);
        logger.infof("session-client-count: %s", userSessionCountForClient);

        // First check if the user has too many sessions in this realm
        if (exceedsLimit(userSessionCountForRealm, userRealmLimit)) {
            logger.info("Too many session in this realm for the current user.");
            handleLimitExceeded(context, userSessionsForRealm);
        }
        // otherwise if the user is still allowed to create a new session in the realm, check if this applies for this specific client as well.
        else if (exceedsLimit(userSessionCountForClient, userClientLimit)) {
            logger.info("Too many sessions related to the current client for this user.");
            handleLimitExceeded(context, userSessionsForClient);
        }
        else {
            context.success();
        }
    }

    private void handleLimitExceeded(AuthenticationFlowContext context, List<UserSessionModel> userSessions) {
        switch (behavior) {
            case UserSessionLimitsAuthenticatorFactory.DENY_NEW_SESSION:
                logger.info("Denying new session");
                context.failure(AuthenticationFlowError.SESSION_LIMIT_EXCEEDED);
                break;
            case UserSessionLimitsAuthenticatorFactory.TERMINATE_OLDEST_SESSION:
                logger.info("Terminating oldest session");
                logoutOldestSession(userSessions);
                context.success();
                break;
        }
    }

    private void logoutOldestSession(List<UserSessionModel> userSessions) {
        logger.info("Logging out oldest session");
        Optional<UserSessionModel> oldest = userSessions.stream().sorted(Comparator.comparingInt(UserSessionModel::getStarted)).findFirst();
        oldest.ifPresent(userSession -> AuthenticationManager.backchannelLogout(session, userSession, true));
    }
}
