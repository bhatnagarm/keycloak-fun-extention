package org.keycloak.authentication.spi.authenticate;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.authentication.spi.MobileAuthConstants;
import org.keycloak.authentication.spi.SmsAuthConstants;
import org.keycloak.authentication.spi.VerifyUserConstant;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class VerifyFirstTimeAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "verify-first-time-authenticator";
    private static final VerifyFirstTimeAuthenticator SINGLETON = new VerifyFirstTimeAuthenticator();
    private static final Logger log = Logger
            .getLogger(VerifyFirstTimeAuthenticatorFactory.class.getPackage().getName());

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED,
            AuthenticationExecutionModel.Requirement.CONDITIONAL,
    };

    private static final List<ProviderConfigProperty> configProperties;

    static {
        configProperties = ProviderConfigurationBuilder
                .create()

                .property()
                .name(VerifyUserConstant.REDIRECT_URL_FIRSTTIME)
                .label("Redirect URL FirstTime Login")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("The redirect URL for First Time user.")
                .add()

                .property()
                .name(MobileAuthConstants.LOGIN_ASSISTANCE_URL)
                .label("Redirect URL Fail FirstTime login ")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("Redirect URL Fail FirstTime login ")
                .add()

                .property()
                .name(SmsAuthConstants.ACCOUNT_SID)
                .label("Account Sid")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("The SID of the Account that created the Verification resource.")
                .add()

                .property()
                .name(SmsAuthConstants.AUTH_TOKEN)
                .label("Authentication Token")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("Unique Auth token for Twilio account")
                .add()

                .property()
                .name(SmsAuthConstants.SERVICE_SID)
                .label("Service SID Token")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("Unique Service ID for Twilio account")
                .add()

                .property()
                .name(SmsAuthConstants.SMS_ENABLED)
                .label("SMS Enabled")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .helpText("Is the SMS Enabled on this environment")
                .add()

                .build();
    }

    /**
     * Friendly name for the authenticator
     *
     * @return
     */
    @Override
    public String getDisplayType() {
        return "A&G First Time Login Authentication";
    }

    /**
     * General authenticator type, i.e. totp, password, cert.
     *
     * @return null if not a referencable category
     */
    @Override
    public String getReferenceCategory() {
        return null;
    }

    /**
     * Is this authenticator configurable?
     *
     * @return
     */
    @Override
    public boolean isConfigurable() {
        return true;
    }

    /**
     * What requirement settings are allowed.
     *
     * @return
     */
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES == null ? null : REQUIREMENT_CHOICES.clone();
    }

    /**
     * Does this authenticator have required actions that can set if the user does not have
     * this authenticator set up?
     *
     * @return
     */
    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "First time Authenticator for Auto & General.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    /**
     * Only called once when the factory is first created.  This config is pulled from keycloak_server.json
     *
     * @param config
     */
    @Override
    public void init(Config.Scope config) {
        log.info("VerifyFirstTimeAuthenticatorFactory - Method [init]");
    }

    /**
     * Called after all provider factories have been initialized
     *
     * @param factory
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        log.info("VerifyFirstTimeAuthenticatorFactory - Method [postInit]");
    }

    /**
     * This is called when the server shuts down.
     */
    @Override
    public void close() {
        log.info("<<<<<<<<<<<<<<< VerifyFirstTimeAuthenticatorFactory close");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
