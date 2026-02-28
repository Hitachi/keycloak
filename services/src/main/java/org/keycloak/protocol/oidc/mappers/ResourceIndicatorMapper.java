package org.keycloak.protocol.oidc.mappers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.Profile;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.utils.RoleResolveUtil;

import org.jboss.logging.Logger;

/**
 * Built-in protocol mapper that resolves OAuth 2.0 Resource Indicators (RFC 8707) to audience claims.
 *
 * When a {@code resource} parameter is present in the authorization request, this mapper:
 * <ol>
 *   <li>Looks up the client with a matching {@code resource.indicator.uri} attribute</li>
 *   <li>Verifies the user has at least one client role from that target client</li>
 *   <li>Adds the resource URI to the access token's {@code aud} claim</li>
 * </ol>
 *
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class ResourceIndicatorMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, TokenIntrospectionTokenMapper, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "oidc-resource-indicator-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    private static final Logger logger = Logger.getLogger(ResourceIndicatorMapper.class);

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, ResourceIndicatorMapper.class);
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Resource Indicator Resolve";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Resolves OAuth2 Resource Indicators (RFC 8707) to audience claims. " +
                "Adds the resource URI to the audience if a client with a matching resource indicator URI exists " +
                "and the user has at least one client role from that client.";
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.RESOURCE_INDICATOR);
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        if (clientSessionCtx == null || clientSessionCtx.getClientSession() == null) {
            return;
        }
        String resource = clientSessionCtx.getClientSession().getNote(OAuth2Constants.RESOURCE);
        if (resource == null || resource.isBlank()) {
            return;
        }

        RealmModel realm = keycloakSession.getContext().getRealm();
        String requestingClientId = clientSessionCtx.getClientSession().getClient().getClientId();

        // Find the client with matching resource indicator URI
        ClientModel targetClient = findClientByResourceIndicatorUri(keycloakSession, realm, resource);
        if (targetClient == null) {
            logger.debugv("No client found with resource indicator URI: {0}", resource);
            return;
        }

        String targetClientId = targetClient.getClientId();

        // If the target client is the requesting client itself, add the resource URI
        if (targetClientId.equals(requestingClientId)) {
            token.addAudience(resource);
            return;
        }

        // Check if user has role access to the target client
        Map<String, AccessToken.Access> resolvedRoles = RoleResolveUtil.getAllResolvedClientRoles(keycloakSession, clientSessionCtx);
        AccessToken.Access access = resolvedRoles.get(targetClientId);
        if (access != null && access.getRoles() != null && !access.getRoles().isEmpty()) {
            token.addAudience(resource);
        } else {
            logger.debugv("User does not have role access to target client {0} for resource {1}", targetClientId, resource);
        }
    }

    /**
     * Find a client by its resource indicator URI attribute.
     */
    static ClientModel findClientByResourceIndicatorUri(KeycloakSession session, RealmModel realm, String resourceUri) {
        Map<String, String> attrs = Map.of(OIDCConfigAttributes.RESOURCE_INDICATOR_URI, resourceUri);
        return session.clients()
                .searchClientsByAttributes(realm, attrs, null, null)
                .findFirst()
                .orElse(null);
    }

    public static ProtocolMapperModel createClaimMapper(String name, boolean accessToken, boolean introspectionEndpoint) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        if (accessToken) {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        } else {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "false");
        }
        if (introspectionEndpoint) {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION, "true");
        } else {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION, "false");
        }
        mapper.setConfig(config);
        return mapper;
    }
}
