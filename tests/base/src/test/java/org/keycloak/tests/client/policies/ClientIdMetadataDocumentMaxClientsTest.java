package org.keycloak.tests.client.policies;

import java.util.List;

import org.keycloak.common.Profile;
import org.keycloak.protocol.oauth2.cimd.clientpolicy.condition.ClientIdUriSchemeCondition;
import org.keycloak.protocol.oauth2.cimd.clientpolicy.condition.ClientIdUriSchemeConditionFactory;
import org.keycloak.protocol.oauth2.cimd.clientpolicy.executor.AbstractClientIdMetadataDocumentExecutor;
import org.keycloak.protocol.oauth2.cimd.clientpolicy.executor.AbstractClientIdMetadataDocumentExecutorFactory;
import org.keycloak.protocol.oauth2.cimd.clientpolicy.executor.ClientIdMetadataDocumentExecutor;
import org.keycloak.protocol.oauth2.cimd.clientpolicy.executor.ClientIdMetadataDocumentExecutorFactory;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.ClientPolicyConditionConfigurationRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectUser;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.oauth.CimdProvider;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.OAuthIdentityProvider;
import org.keycloak.testframework.oauth.OIDCClientRepresentationBuilder;
import org.keycloak.testframework.oauth.annotations.InjectCimdProvider;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthIdentityProvider;
import org.keycloak.testframework.realm.ClientPolicyBuilder;
import org.keycloak.testframework.realm.ClientProfileBuilder;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.ManagedUser;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorSpi;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.page.ErrorPage;
import org.keycloak.tests.oauth.AbstractJWTAuthorizationGrantTest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests CIMD max-clients enforcement.
 *
 * <p>The max-clients limit is a factory global setting. This test class uses a server configuration
 * that sets max-clients=1 so that any realm already containing at least one client (which Keycloak
 * guarantees via built-in realm clients) will immediately reject CIMD client registration.
 *
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
@KeycloakIntegrationTest(config = ClientIdMetadataDocumentMaxClientsTest.CimdMaxClientsServerConfig.class)
public class ClientIdMetadataDocumentMaxClientsTest {

    private static final String CLIENT_ID = "http://localhost:8500/cimd/metadata";
    private static final String REDIRECT_URI = "http://localhost:8500/";
    private static final String JWKS_URI = "http://localhost:8500/idp/jwks";

    @InjectRealm
    protected ManagedRealm realm;

    @InjectUser(config = AbstractJWTAuthorizationGrantTest.FederatedUserConfiguration.class)
    protected ManagedUser user;

    @InjectOAuthIdentityProvider
    OAuthIdentityProvider identityProvider;

    @InjectCimdProvider(config = CimdMaxClientsClientConfig.class, lifecycle = LifeCycle.METHOD)
    CimdProvider cimd;

    @InjectOAuthClient
    OAuthClient oauth;

    @InjectPage
    ErrorPage errorPage;

    /**
     * When max-clients=1 (factory global setting) and the realm already contains built-in clients
     * (e.g. realm-management, account, etc.), any CIMD client registration attempt must be rejected
     * with ERR_CLIENTS_LIMIT_REACHED because the total client count is already >= 1.
     */
    @Test
    public void testClientIdMetadataDocumentExecutorMaxClientsLimitReached() {
        // Configure CIMD policy
        ClientIdUriSchemeCondition.Configuration conditionConfig = new ClientIdUriSchemeCondition.Configuration();
        conditionConfig.setClientIdUriSchemes(List.of("http", "https"));
        conditionConfig.setTrustedDomains(List.of("*.example.com", "localhost"));
        ClientIdMetadataDocumentExecutor.Configuration executorConfig = new ClientIdMetadataDocumentExecutor.Configuration();
        executorConfig.setTrustedDomains(List.of("*.example.com", "localhost"));
        executorConfig.setAllowHttpScheme(true);

        realm.updateWithCleanup(r -> {
            r.resetClientProfiles()
                    .clientProfile(ClientProfileBuilder.create()
                    .name("executor")
                    .description("executor description")
                    .executor(ClientIdMetadataDocumentExecutorFactory.PROVIDER_ID, executorConfig)
                    .build());
            r.resetClientPolicies()
                    .clientPolicy(ClientPolicyBuilder.create()
                    .name("policy")
                    .description("description of policy")
                    .condition(ClientIdUriSchemeConditionFactory.PROVIDER_ID, conditionConfig)
                    .profile("executor")
                    .build());
            return r;
        });

        // The realm always has built-in clients (like realm-management, account, etc.),
        // so total clients >= 1 which means CIMD registration must be rejected because max-clients=1
        Assertions.assertTrue(realm.admin().clients().findAll().size() >= 1,
                "Realm must already have at least one client for this test to be meaningful");

        oauth.client(CLIENT_ID);
        oauth.redirectUri(REDIRECT_URI);
        oauth.openLoginForm();
        errorPage.assertCurrent();
        Assertions.assertEquals(AbstractClientIdMetadataDocumentExecutor.ERR_CLIENTS_LIMIT_REACHED,
                errorPage.getError());
    }

    public static class CimdMaxClientsServerConfig implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.features(Profile.Feature.CIMD)
                    .spiOption(ClientPolicyExecutorSpi.SPI_NAME,
                            ClientIdMetadataDocumentExecutorFactory.PROVIDER_ID,
                            AbstractClientIdMetadataDocumentExecutorFactory.CONFIG_MAX_CLIENTS,
                            "1");
        }
    }

    public static class CimdMaxClientsClientConfig implements OIDCClientRepresentationBuilder {
        @Override
        public OIDCClientRepresentation build() {
            OIDCClientRepresentation client = new OIDCClientRepresentation();
            client.setClientId(CLIENT_ID);
            client.setRedirectUris(List.of(REDIRECT_URI));
            client.setJwksUri(JWKS_URI);
            client.setClientName("sample");
            client.setClientUri("http://localhost:8500");
            client.setTokenEndpointAuthMethod(OIDCLoginProtocol.PRIVATE_KEY_JWT);
            client.setGrantTypes(List.of("authorization_code", "refresh_token"));
            return client;
        }
    }
}
