package org.keycloak.tests.oauth;

import java.io.IOException;

import org.keycloak.OAuthErrorException;
import org.keycloak.common.Profile;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.RealmConfigBuilder;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.page.LogoutConfirmPage;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.testsuite.util.oauth.IntrospectionResponse;
import org.keycloak.testsuite.util.oauth.TokenRevocationResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;


@KeycloakIntegrationTest(config = ResourceIndicatorMapperTest.ResourceIndicatorMapperServerConfig.class)
@TestMethodOrder(MethodOrderer.MethodName.class)
public class ResourceIndicatorMapperTest {

    @InjectRealm(config = ResourceIndicatorMapperRealmConfig.class)
    ManagedRealm testRealm;

    @InjectOAuthClient
    OAuthClient oAuthClient;

    @InjectRunOnServer
    RunOnServerClient runOnServer;

    @InjectPage
    protected LogoutConfirmPage logoutConfirmPage;

    private static final String TEST_REALM = "MyTestRealm";
    private static final String TEST_CLIENT = "MyTestClient";
    private static final String TEST_CLIENT_SECRET = "secret";
    private static final String TEST_USER = "MyTestUser";
    private static final String TEST_USER_PASSWORD = "password";

    private static final String RESOURCE_SERVER_CLIENT = "MyResourceServer";
    private static final String RESOURCE_SERVER_URI = "https://resource.example.com/v1";
    private static final String RESOURCE_SERVER_ROLE = "access";

    @BeforeEach
    public void setup() {
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName(TEST_REALM);

            // Set up resource server client with resource indicator URI
            ClientModel resourceServer = realm.getClientByClientId(RESOURCE_SERVER_CLIENT);
            if (resourceServer == null) {
                resourceServer = realm.addClient(RESOURCE_SERVER_CLIENT);
                resourceServer.setEnabled(true);
                resourceServer.setStandardFlowEnabled(false);
                resourceServer.setDirectAccessGrantsEnabled(false);
                OIDCAdvancedConfigWrapper.fromClientModel(resourceServer)
                        .setResourceIndicatorUri(RESOURCE_SERVER_URI);

                // Add a role to the resource server
                RoleModel role = resourceServer.addRole(RESOURCE_SERVER_ROLE);

                // Assign the role to the test user
                UserModel user = session.users().getUserByUsername(realm, TEST_USER);
                user.grantRole(role);

                // Add the resource server's role to the test client's scope
                ClientModel testClient = realm.getClientByClientId(TEST_CLIENT);
                testClient.addScopeMapping(role);
            }

            // disable verify profile required action
            RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(UserModel.RequiredAction.VERIFY_PROFILE.name());
            if (model.isEnabled()) {
                model.setDefaultAction(false);
                model.setEnabled(false);
                realm.updateRequiredActionProvider(model);
            }
        });
    }

    @AfterEach
    public void cleanup() {
        // logout
        oAuthClient.openLogoutForm();
        logoutConfirmPage.assertCurrent();
        logoutConfirmPage.confirmLogout();
    }

    @Test
    public void testResourceIndicatorAddedToAudience() throws IOException {
        // Authorization code grant with resource parameter
        // -> resource URI should be added to aud claim
        String code = loginUserAndGetCode(TEST_CLIENT, RESOURCE_SERVER_URI);
        AccessTokenResponse tokenResponse = oAuthClient
                .client(TEST_CLIENT, TEST_CLIENT_SECRET).accessTokenRequest(code).resource(RESOURCE_SERVER_URI).send();
        assertTokenValidResponse(tokenResponse, RESOURCE_SERVER_URI);

        // introspect
        IntrospectionResponse introspectionResponse = oAuthClient.doIntrospectionAccessTokenRequest(tokenResponse.getAccessToken());
        assertIntrospectValidResponse(introspectionResponse, RESOURCE_SERVER_URI);

        // refresh - resource URI from auth request should persist
        tokenResponse = oAuthClient.doRefreshTokenRequest(tokenResponse.getRefreshToken());
        assertRefreshTokenResponse(tokenResponse, RESOURCE_SERVER_URI);

        // revoke
        TokenRevocationResponse revokeResponse = oAuthClient.doTokenRevoke(tokenResponse.getAccessToken());
        assertRevokeValidResponse(revokeResponse, tokenResponse);
    }

    @Test
    public void testNoResourceParameter() {
        // Authorization code grant without resource parameter
        // -> no resource URI in aud claim
        String code = loginUserAndGetCode(TEST_CLIENT, null);
        AccessTokenResponse tokenResponse = oAuthClient
                .client(TEST_CLIENT, TEST_CLIENT_SECRET).accessTokenRequest(code).send();
        assertNotBindTokenValidResponse(tokenResponse);
    }

    @Test
    public void testInvalidResourceParameter() {
        // Authorization code grant with invalid resource URI (no matching client)
        // -> error at authorization endpoint
        String unknownResource = "https://unknown.example.com/api";
        assertLoginError(TEST_CLIENT, unknownResource, OAuthErrorException.INVALID_TARGET,
                "Invalid resource indicator: " + unknownResource);
    }

    @Test
    public void testResourceIndicatorWithoutRoleAccess() {
        // Remove the role from the user, then try
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName(TEST_REALM);
            ClientModel resourceServer = realm.getClientByClientId(RESOURCE_SERVER_CLIENT);
            RoleModel role = resourceServer.getRole(RESOURCE_SERVER_ROLE);
            UserModel user = session.users().getUserByUsername(realm, TEST_USER);
            user.deleteRoleMapping(role);
        });

        // Authorization code grant with resource parameter - client exists but user has no role
        // -> resource URI should NOT be in aud claim (silently skipped)
        String code = loginUserAndGetCode(TEST_CLIENT, RESOURCE_SERVER_URI);
        AccessTokenResponse tokenResponse = oAuthClient
                .client(TEST_CLIENT, TEST_CLIENT_SECRET).accessTokenRequest(code).resource(RESOURCE_SERVER_URI).send();
        assertNotBindTokenValidResponse(tokenResponse);

        // Restore the role
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName(TEST_REALM);
            ClientModel resourceServer = realm.getClientByClientId(RESOURCE_SERVER_CLIENT);
            RoleModel role = resourceServer.getRole(RESOURCE_SERVER_ROLE);
            UserModel user = session.users().getUserByUsername(realm, TEST_USER);
            user.grantRole(role);
        });
    }

    public static class ResourceIndicatorMapperRealmConfig implements RealmConfig {

        @Override
        public RealmConfigBuilder configure(RealmConfigBuilder realm) {
            realm.name(TEST_REALM);
            realm.addClient(TEST_CLIENT).secret(TEST_CLIENT_SECRET).redirectUris("http://127.0.0.1:8500/callback/oauth");
            realm.addUser(TEST_USER).password(TEST_USER_PASSWORD);
            return realm;
        }
    }

    public static class ResourceIndicatorMapperServerConfig implements KeycloakServerConfig {

        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.features(Profile.Feature.RESOURCE_INDICATOR);
        }
    }

    private String loginUserAndGetCode(String clientId, String resource) {
        oAuthClient.client(clientId);
        oAuthClient.loginForm().resource(resource).doLogin(TEST_USER, TEST_USER_PASSWORD);

        String code = oAuthClient.parseLoginResponse().getCode();
        Assertions.assertNotNull(code);
        return code;
    }

    private String ssoLoginUserAndGetCode(String clientId, String resource) {
        oAuthClient.client(clientId);
        oAuthClient.loginForm().resource(resource).open();

        String code = oAuthClient.parseLoginResponse().getCode();
        Assertions.assertNotNull(code);
        return code;
    }

    private void assertTokenValidResponse(AccessTokenResponse tokenResponse, String resource) {
        Assertions.assertEquals(200, tokenResponse.getStatusCode());
        AccessToken accessToken = oAuthClient.verifyToken(tokenResponse.getAccessToken());
        Assertions.assertNotNull(accessToken.getAudience(), "Expected audience in access token");
        boolean found = false;
        for (String aud : accessToken.getAudience()) {
            if (resource.equals(aud)) {
                found = true;
                break;
            }
        }
        Assertions.assertTrue(found, "Expected resource " + resource + " in audience");
        IDToken idToken = oAuthClient.verifyIDToken(tokenResponse.getIdToken());
        Assertions.assertEquals(1, idToken.getAudience().length);
        Assertions.assertEquals(TEST_CLIENT, idToken.getAudience()[0]);
    }

    private void assertIntrospectValidResponse(IntrospectionResponse introspectionResponse, String resource) throws IOException {
        Assertions.assertEquals(200, introspectionResponse.getStatusCode());
        String[] aud = introspectionResponse.asTokenMetadata().getAudience();
        Assertions.assertNotNull(aud);
        boolean found = false;
        for (String a : aud) {
            if (resource.equals(a)) {
                found = true;
                break;
            }
        }
        Assertions.assertTrue(found, "Expected resource " + resource + " in introspection audience");
    }

    private void assertRefreshTokenResponse(AccessTokenResponse tokenResponse, String resource) {
        Assertions.assertEquals(200, tokenResponse.getStatusCode());
        AccessToken accessToken = oAuthClient.verifyToken(tokenResponse.getAccessToken());
        Assertions.assertNotNull(accessToken.getAudience(), "Expected audience in refreshed token");
        boolean found = false;
        for (String aud : accessToken.getAudience()) {
            if (resource.equals(aud)) {
                found = true;
                break;
            }
        }
        Assertions.assertTrue(found, "Expected resource " + resource + " in refreshed token audience");
    }

    private void assertRevokeValidResponse(TokenRevocationResponse revokeResponse, AccessTokenResponse tokenResponse) throws IOException {
        Assertions.assertEquals(200, revokeResponse.getStatusCode());
        IntrospectionResponse introspectionResponse = oAuthClient.doIntrospectionAccessTokenRequest(tokenResponse.getAccessToken());
        Assertions.assertEquals(200, introspectionResponse.getStatusCode());
        Assertions.assertFalse(introspectionResponse.asTokenMetadata().isActive());
    }

    private void assertNotBindTokenValidResponse(AccessTokenResponse tokenResponse) {
        Assertions.assertEquals(200, tokenResponse.getStatusCode());
        AccessToken accessToken = oAuthClient.verifyToken(tokenResponse.getAccessToken());
        if (accessToken.getAudience() != null) {
            for (String aud : accessToken.getAudience()) {
                Assertions.assertNotEquals(RESOURCE_SERVER_URI, aud, "Resource URI should not be in audience");
            }
        }
    }

    private void assertLoginError(String clientId, String resource, String error, String errorDescription) {
        oAuthClient.client(clientId);
        oAuthClient.loginForm().resource(resource).open();

        AuthorizationEndpointResponse authorizationEndpointResponse = oAuthClient.parseLoginResponse();
        Assertions.assertEquals(error, authorizationEndpointResponse.getError());
        Assertions.assertEquals(errorDescription, authorizationEndpointResponse.getErrorDescription());
    }
}
