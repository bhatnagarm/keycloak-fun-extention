package org.keycloak.authentication.spi.authenticate;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.spi.*;
import org.keycloak.authentication.spi.sms.SmsSendVerify;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

public class VerifyFirstTimeAuthenticator implements Authenticator {
    private static final Logger log = Logger.getLogger(VerifyFirstTimeAuthenticator.class.getPackage().getName());
    private transient SmsSendVerify sendVerify;
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
    public void authenticate(AuthenticationFlowContext context) {
        log.error("VerifyFirstTimeAuthenticator - Method [authenticate]");

        final UserModel user = context.getUser();
        final String mobileNumber = getMobileNumber(user);
        log.errorv("VerifyFirstTimeAuthenticator - mobileNumber : {0}", mobileNumber);

        if (mobileNumber != null) {
            if (CustomKeycloakUtils
                    .getConfigBoolean(context.getAuthenticatorConfig(), SmsAuthConstants.SMS_ENABLED)) {
                log.error("VerifyFirstTimeAuthenticator - Method [authenticate] : Inside SMS Enabled Space.");
                // SendSMS
                sendVerify = new SmsSendVerify(CustomKeycloakUtils.getConfigString(context.getAuthenticatorConfig(),
                        SmsAuthConstants.ACCOUNT_SID),
                        CustomKeycloakUtils.getConfigString(context.getAuthenticatorConfig(), SmsAuthConstants.AUTH_TOKEN),
                        CustomKeycloakUtils.getConfigString(context.getAuthenticatorConfig(), SmsAuthConstants.SERVICE_SID));
                sendVerify.sendOtp(this.convertTelephoneNumber(mobileNumber));
            }

            try {
                redirectLogin(context);
            } catch (Exception ex) {
                log.error("Redirect blunder");
            }

        } else {
            try {
                redirectFailCase(context);
            } catch (Exception ex) {
                log.error("Redirect blunder");
            }
        }


    }

    /**
     * Called from a form action invocation.
     *
     * @param context
     */
    @Override
    public void action(final AuthenticationFlowContext context) {
        log.error("VerifyFirstTimeAuthenticator - Method [action]");

        final MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        final String firstName = inputData.getFirst(VerifyUserConstant.FIRST_NAME);
        final String lastName = inputData.getFirst(VerifyUserConstant.LAST_NAME);

        final UserModel user = context.getUser();
        if (isValidUser(user.getAttributes(),firstName, lastName)) {
            final String mobileNumber = getMobileNumber(user);
            log.errorv("VerifyFirstTimeAuthenticator - phoneNumber : {0}", mobileNumber);
            if(CustomKeycloakUtils
                    .getConfigBoolean(context.getAuthenticatorConfig(), SmsAuthConstants.SMS_ENABLED)) {

                if (sendVerify.receivePin(mobileNumber, inputData.getFirst(VerifyUserConstant.ENTERED_PIN))) {
                    log.error("VerifyFirstTimeAuthenticator - verify code check : OK");
                    context.success();
                } else {
                    try {
                        redirectLogin(context);
                    } catch (Exception ex) {
                        log.error("Redirect blunder");
                    }
                }
            } else {
                log.error("VerifyFirstTimeAuthenticator - Method [action] : SMS Auth not enabled");
                context.success();
            }


        } else {
            try {
                redirectFailCase(context);
                context.cancelLogin();
            } catch (URISyntaxException e) {
                log.error("Failed to login. Exception in URL cast.");
            }
        }


    }

    /**
     * Does this authenticator require that the user has already been identified?  That AuthenticatorContext.getUser() is not null?
     *
     * @return
     */
    @Override
    public boolean requiresUser() {
        log.error("VerifyFirstTimeAuthenticator - Method [requiresUser]");
        return true;
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
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    /**
     * Set actions to configure authenticator
     *
     * @param session
     * @param realm
     * @param user
     */
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {
        log.info("<<<<<<<<<<<<<<< VerifyFirstTimeAuthenticator close");

    }

    private void redirectLogin(final AuthenticationFlowContext context) throws URISyntaxException,
            UnsupportedEncodingException {
        log.info("VerifyFirstTimeAuthenticator - Method [redirect]");

        final String redirect_url = CustomKeycloakUtils.getConfigString(context.getAuthenticatorConfig(),
                VerifyUserConstant.REDIRECT_URL_FIRSTTIME);
        log.info("VerifyFirstTimeAuthenticator - Method [redirect] : getRedirectURL" + redirect_url);

        final String testURL = context.getActionUrl(context.generateAccessCode()).toASCIIString();
        log.info("VerifyFirstTimeAuthenticator - Method [redirect] : getTestURL" + testURL);
        final String encodedUrl = CustomKeycloakUtils.encodeValue(testURL);
        log.info("VerifyFirstTimeAuthenticator - Method [redirect] : getEncodedURL" + encodedUrl);
        final String modifiedRedirectUrl = String.format(redirect_url, encodedUrl);

        log.info("VerifyFirstTimeAuthenticator - Method [redirect] : modifiedRedirectUrl" + modifiedRedirectUrl);

        final URI location = new URI(modifiedRedirectUrl);
        log.info("VerifyFirstTimeAuthenticator - Method [redirect] : modifiedRedirectUrl");
        final Response response = Response.seeOther(location).build();
        log.info("VerifyFirstTimeAuthenticator - Method [redirect] : Response Redirected");
        context.forceChallenge(response);
    }

    private void redirectFailCase(final AuthenticationFlowContext context) throws URISyntaxException {
        final String failureUrl = CustomKeycloakUtils.getConfigString(context.getAuthenticatorConfig(),
                MobileAuthConstants.LOGIN_ASSISTANCE_URL);
        final URI location = new URI(failureUrl);
        final Response response = Response.seeOther(location).build();
        context.forceChallenge(response);
    }

    private static boolean getMobileNumberVerify(final String mobileNumber) {
        return mobileNumber.matches("^04\\d{8}");
    }

    private String getMobileNumber(final UserModel user) {
        final List<String> phoneNumberList = user.getAttribute(SmsAuthConstants.ATTR_MOBILE);
        if (phoneNumberList != null && !phoneNumberList.isEmpty()) {
            return phoneNumberList.get(0);
        }
        return null;
    }

    private boolean isValidUser(final Map<String, List<String>> attributes,
                                final String firstName,
                                final String lastName) {
        return check(attributes.get(UserAttributesConstants.LOCAL_FIRST_NAME), firstName)
                && check(attributes.get(UserAttributesConstants.LOCAL_LAST_NAME), lastName);
    }

    boolean check(Collection<String> existingNames, String name) {
        Predicate<String> equalityPred = name==null? Objects::isNull:
                name::equalsIgnoreCase;

        return existingNames.stream().anyMatch(equalityPred);
    }

    private String convertTelephoneNumber(final String mobileNumber) {
        return mobileNumber.replaceFirst("04", "+614");
    }

}
