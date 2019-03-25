package org.keycloak.authentication.authenticators.sessionlimits;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;

import java.util.Map;

public class RealmSessionLimitsAuthenticator extends AbstractSessionLimitsAuthenticator {
    private static Logger logger = Logger.getLogger(RealmSessionLimitsAuthenticator.class);


    public RealmSessionLimitsAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        Map<String, String> config = authenticatorConfig.getConfig();
        String behavior = config.get(RealmSessionLimitsAuthenticatorFactory.BEHAVIOR);
        int realmLimit = getIntConfigProperty(RealmSessionLimitsAuthenticatorFactory.REALM_LIMIT, config);

        Map<String, Long> activeClientSessionStats = session.sessions().getActiveClientSessionStats(context.getRealm(), false);
        long realmSessionCount = activeClientSessionStats.values().stream().reduce(0L, Long::sum);

        logger.infof("realm limit: %s", realmLimit);
        logger.infof("session-realm-count: %s", realmSessionCount);

        if (exceedsLimit(realmSessionCount, realmLimit)) {
            logger.infof("Session count exceeded configured limit for realm. Count: %n, Limit: %i, Realm: %s", realmSessionCount, realmLimit, context.getRealm().getDisplayName());
            if (RealmSessionLimitsAuthenticatorFactory.DENY_NEW_SESSION.equals(behavior)) {
                context.failure(AuthenticationFlowError.SESSION_LIMIT_EXCEEDED);
                logger.infof("Denying access to user because the maximum number of sessions for this realm has been reached. Configured maximum: %i", realmLimit);
                return;
            }
        }
        context.attempted();
    }
}
