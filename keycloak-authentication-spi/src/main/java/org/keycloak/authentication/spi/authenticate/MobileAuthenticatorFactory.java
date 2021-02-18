package org.keycloak.authentication.spi.authenticate;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.authentication.spi.MobileAuthConstants;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class MobileAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "mobile-authenticator";
    private static final MobileAuthenticator SINGLETON = new MobileAuthenticator();
    private static final Logger log = Logger.getLogger(MobileAuthenticatorFactory.class.getPackage().getName());

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> configProperties;

    static {
        configProperties = ProviderConfigurationBuilder
                .create()

                .property()
                .name(MobileAuthConstants.REDIRECT_URL)
                .label("Redirect URL")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("This is the URL we redirect to.")
                .add()

                .property()
                .name(MobileAuthConstants.LOGIN_ASSISTANCE_URL)
                .label("Login Fail URL")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("This is the URL we redirect to when login fails.")
                .add()

                .property()
                .name(MobileAuthConstants.LOGIN_SYSTEM_ERROR)
                .label("Login System Error URL")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("This is the URL we redirect to when login fails due to system failure.")
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
        return "A&G Mobile Authentication";
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
        return "Mobile Authenticate for Auto & General.";
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
        log.error("MobileAuthenticatorFactory - Method [init]");
    }

    /**
     * Called after all provider factories have been initialized
     *
     * @param factory
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        log.info("MobileAuthenticatorFactory - Method [postInit]");
    }

    /**
     * This is called when the server shuts down.
     */
    @Override
    public void close() {
        log.info("<<<<<<<<<<<<<<< MobileAuthenticatorFactory close");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
