package org.keycloak.authentication.spi.authenticate;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.spi.CustomKeycloakUtils;
import org.keycloak.authentication.spi.MobileAuthConstants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class MobileAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(MobileAuthenticator.class);
    private static final String LOGIN_ATTEMPTS = "LOGIN_ATTEMPTS";

    /**
     * Initial call for the authenticator.  This method should check the current HTTP request to determine if the request
     * satifies the Authenticator's requirements.  If it doesn't, it should send back a challenge response by calling
     * the AuthenticationFlowContext.challenge(Response).  If this challenge is a authentication, the action URL
     * of the form must point to
     * <p>
     * /realms/{realm}/login-actions/authenticate?code={session-code}&execution={executionId}
     * <p>
     * or
     * <p>
     * /realms/{realm}/login-actions/registration?code={session-code}&execution={executionId}
     * <p>
     * {session-code} pertains to the code generated from AuthenticationFlowContext.generateAccessCode().  The {executionId}
     * pertains to the AuthenticationExecutionModel.getId() value obtained from AuthenticationFlowContext.getExecution().
     * <p>
     * The action URL will invoke the action() method described below.
     *
     * @param context
     */
    @Override
    public void authenticate(final AuthenticationFlowContext context) {
        log.info("MobileAuthenticator - Method [authenticate]");
        try {

            redirectLogin(context);
        } catch (Exception e) {
            log.error("Redirect blunder");
        }

    }

    /**
     * Called from a form action invocation.
     *
     * @param context
     */
    @Override
    public void action(final AuthenticationFlowContext context) {
        try {
            log.info("MobileAuthenticator - Method [action]");
            final HttpRequest httpRequest = context.getHttpRequest();

            final MultivaluedMap<String, String> formData = httpRequest.getDecodedFormParameters();

            final String mobileNumber = formData.getFirst("mobile-number");
            final String dateOfBirth = formData.getFirst("date-of-birth");

            final Optional<UserModel> userModelOptional = getUserModel(context, mobileNumber, dateOfBirth);

            if (userModelOptional.isEmpty()) {
                redirectFailCase(context);

            } else {
                context.setUser(userModelOptional.get());
                context.success();
            }

        } catch (Throwable throwable) {
            log.error("Major error thrown" + throwable.getMessage());
            try {
                if (context.getAuthenticationSession().getAuthNote(LOGIN_ATTEMPTS) != null) {
                    redirectTechnicalCase(context,
                            Integer.parseInt(context.getAuthenticationSession().getAuthNote(LOGIN_ATTEMPTS)));
                } else {
                    context.getAuthenticationSession().setAuthNote(LOGIN_ATTEMPTS, "0");
                    redirectTechnicalCase(context,
                            Integer.parseInt(context.getAuthenticationSession().getAuthNote(LOGIN_ATTEMPTS)));
                }
            } catch (URISyntaxException | UnsupportedEncodingException e) {
                log.error("Failed to login. Exception in URL cast.");

            }

        } finally {
            log.error("Failed to login. Exception in URL cast.");
        }


    }

    /**
     * Does this authenticator require that the user has already been identified?  That AuthenticatorContext.getUser() is not null?
     *
     * @return
     */
    @Override
    public boolean requiresUser() {
        return false;
    }

    /**
     * Is this authenticator configured for this user.
     *
     * @param session
     * @param realm
     * @param user
     * @return
     */
    @Override
    public boolean configuredFor(final KeycloakSession session, final RealmModel realm, final UserModel user) {
        log.info("MobileAuthenticator - Method [configuredFor]");
        return true;
    }

    /**
     * Set actions to configure authenticator
     *
     * @param session
     * @param realm
     * @param user
     */
    @Override
    public void setRequiredActions(final KeycloakSession session, final RealmModel realm, final UserModel user) {
    }

    @Override
    public void close() {
        log.error("<<<<<<<<<<<<<<< MobileAuthenticator close");
    }

    private void redirectFailCase(final AuthenticationFlowContext context) throws URISyntaxException, UnsupportedEncodingException {
        final String failureUrl = CustomKeycloakUtils.getConfigString(context.getAuthenticatorConfig(),
                MobileAuthConstants.LOGIN_ASSISTANCE_URL);
        final URI location = new URI(failureUrl);
        final Response response = Response.seeOther(location).build();
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
    }

    private void redirectTechnicalCase(final AuthenticationFlowContext context, int attempts) throws URISyntaxException, UnsupportedEncodingException {
        context.getAuthenticationSession().setAuthNote(LOGIN_ATTEMPTS, String.valueOf(++attempts));
        final String failureUrl = CustomKeycloakUtils.getConfigString(context.getAuthenticatorConfig(),
                MobileAuthConstants.LOGIN_SYSTEM_ERROR);
        final String encodedUrl = CustomKeycloakUtils.encodeValue(context.getActionUrl(context.generateAccessCode())
                .toASCIIString());
        final String modifiedFailureUrl = String.format(failureUrl,context.getExecution().getId(),
                context.getAuthenticationSession().getClient().getClientId(),
                context.getAuthenticationSession().getTabId(),
                encodedUrl, generateState(attempts));
        final URI location = new URI(modifiedFailureUrl);
        final Response response = Response.seeOther(location).build();
        context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, response);
    }

    private void redirectLogin(final AuthenticationFlowContext context) throws URISyntaxException, UnsupportedEncodingException {
        log.info("MobileAuthenticator - Method [redirect]");

        final String redirect_url = CustomKeycloakUtils.getConfigString(context.getAuthenticatorConfig(),
                MobileAuthConstants.REDIRECT_URL);
        log.info("MobileAuthenticator - Method [redirect] : getRedirectURL" + redirect_url);

        final String encodedUrl = CustomKeycloakUtils.encodeValue(context.getActionUrl(context.generateAccessCode())
                .toASCIIString());
        final String modifiedRedirectUrl = String.format(redirect_url, encodedUrl);

        final URI location = new URI(modifiedRedirectUrl);
        final Response response = Response.seeOther(location).build();

        context.forceChallenge(response);
    }

    private Optional<UserModel> getUserModel(final AuthenticationFlowContext context, final String mobileNumber,
                                             final String dateOfBirth) {

        final List<UserModel> users = context.getSession().userStorageManager()
                .searchForUser(Map.of(
                        "mobile", mobileNumber,
                        "dateOfBirth", dateOfBirth),
                        context.getSession().getContext().getRealm());

        return generateOptionalUserModel(users);
    }

    private static Optional<UserModel> generateOptionalUserModel(final List<UserModel> users) {
        final Optional<UserModel> userModelOptional;
        if (users != null && users.size() != 0 ) {
            userModelOptional = users.stream()
                    .filter(userModel -> userModel.getAttributes().size() > 0)
                    .findFirst();
        } else {
            userModelOptional  = Optional.empty();
        }

        return userModelOptional;
    }

    private static String generateState(int attempts) {
        return attempts == 1 ? "retry" : "error";
    }
}
