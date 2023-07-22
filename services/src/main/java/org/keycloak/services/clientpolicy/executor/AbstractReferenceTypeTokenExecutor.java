/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.services.clientpolicy.executor;

import java.util.function.Consumer;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.endpoints.TokenIntrospectionEndpoint;
import org.keycloak.protocol.oidc.endpoints.TokenRevocationEndpoint;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.LogoutRequestContext;
import org.keycloak.services.clientpolicy.context.TokenIntrospectContext;
import org.keycloak.services.clientpolicy.context.TokenRefreshContext;
import org.keycloak.services.clientpolicy.context.TokenRefreshResponseContext;
import org.keycloak.services.clientpolicy.context.TokenResponseContext;
import org.keycloak.services.clientpolicy.context.TokenRevokeContext;
import org.keycloak.services.clientpolicy.context.UserInfoRequestContext;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public abstract class AbstractReferenceTypeTokenExecutor<T extends ClientPolicyExecutorConfigurationRepresentation> implements ClientPolicyExecutorProvider<T> {

    protected static Logger logger = Logger.getLogger(AbstractReferenceTypeTokenExecutor.class);
    protected static final String ERR_PASS_THROUGH_INTENTIONALLY = "error_pass_through_intentionally";

    protected KeycloakSession session;

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {

        try {
            ClientPolicyEvent event = context.getEvent();

            if (event.equals(ClientPolicyEvent.TOKEN_RESPONSE)) {

                logger.trace("----- Token Response :: creating reference access/refresh tokens");

                TokenResponseContext tokenResponseContext = (TokenResponseContext)context;
                setReferenceTypeTokenBoundWithSelfcontainedTypeToken(tokenResponseContext.getAccessTokenResponseBuilder());

            } else if (event.equals(ClientPolicyEvent.TOKEN_REFRESH_RESPONSE)) {

                logger.trace("----- Token Refresh :: creating reference access/refresh tokens");

                TokenRefreshResponseContext tokenRefreshResponseContext = (TokenRefreshResponseContext)context;
                setReferenceTypeTokenBoundWithSelfcontainedTypeToken(tokenRefreshResponseContext.getAccessTokenResponseBuilder());

            } else if (event.equals(ClientPolicyEvent.TOKEN_REFRESH)) {

                logger.trace("----- Token Refresh :: replace an reference refresh token to an self-contained refresh token");

                TokenRefreshContext tokenRefreshContext = (TokenRefreshContext)context;
                setSelfcontainedTypeTokenBoundWithReferenceTypeToken(tokenRefreshContext.getParams().getFirst(OAuth2Constants.REFRESH_TOKEN),
                        t -> tokenRefreshContext.getParams().putSingle(OAuth2Constants.REFRESH_TOKEN, t),
                        null);

            } else if (event.equals(ClientPolicyEvent.TOKEN_INTROSPECT)) {

                logger.trace("----- Token Introspection :: replace an reference token (access or refresh) to an self-contained token");

                TokenIntrospectContext tokenIntrospectContext = (TokenIntrospectContext)context;
                setSelfcontainedTypeTokenBoundWithReferenceTypeToken(tokenIntrospectContext.getParams().getFirst(TokenIntrospectionEndpoint.PARAM_TOKEN),
                        t -> tokenIntrospectContext.getParams().putSingle(TokenIntrospectionEndpoint.PARAM_TOKEN, t),
                        null);

            } else if (event.equals(ClientPolicyEvent.USERINFO_REQUEST)) {

                logger.trace("----- UserInfo Request :: replace an reference access token to an self-contained access token");

                UserInfoRequestContext userInfoRequestContext = (UserInfoRequestContext)context;
                setSelfcontainedTypeTokenBoundWithReferenceTypeToken(userInfoRequestContext.getTokenForUserInfo().getToken(),
                        t -> userInfoRequestContext.getTokenForUserInfo().setToken(t),
                        null);

            } else if (event.equals(ClientPolicyEvent.TOKEN_REVOKE)) {

                logger.trace("----- Token Revocation :: replace an reference token (access or refresh) to an self-contained token");

                TokenRevokeContext tokenRevokeContext = (TokenRevokeContext)context;
                setSelfcontainedTypeTokenBoundWithReferenceTypeToken(tokenRevokeContext.getParams().getFirst(TokenRevocationEndpoint.PARAM_TOKEN),
                        t -> tokenRevokeContext.getParams().putSingle(TokenRevocationEndpoint.PARAM_TOKEN, t),
                        null);

            } else if (event.equals(ClientPolicyEvent.LOGOUT_REQUEST)) {

                logger.trace("----- Legacy Backchannel Logout :: replace an reference refresh token to an self-contained refresh token");

                LogoutRequestContext logoutRequestContext = (LogoutRequestContext)context;
                setSelfcontainedTypeTokenBoundWithReferenceTypeToken(logoutRequestContext.getParams().getFirst(OAuth2Constants.REFRESH_TOKEN),
                        t -> logoutRequestContext.getParams().putSingle(OAuth2Constants.REFRESH_TOKEN, t),
                        null);

            }
        } catch (ClientPolicyException cpe) {
            // not throw an exception intentionally when the error procedure is up to the caller endpoint class.
            if (!ERR_PASS_THROUGH_INTENTIONALLY.contains(cpe.getError())) throw cpe;
        }
    }

    abstract protected String createReferenceTypeAccessToken(TokenManager.AccessTokenResponseBuilder builder);

    abstract protected String createReferenceTypeRefreshToken(TokenManager.AccessTokenResponseBuilder builder);

    abstract protected String getSelfcontainedTypeToken(String referenceTypeToken, ClientPolicyException exceptionOnInvalidToken) throws ClientPolicyException ;

    abstract protected void bindSelfcontainedTypeToken(String selfcontainedTypeToken, String referenceTypeToken) throws ClientPolicyException;

    private void setReferenceTypeTokenBoundWithSelfcontainedTypeToken(TokenManager.AccessTokenResponseBuilder builder) throws ClientPolicyException {

        String referenceTypeAccessToken = createReferenceTypeAccessToken(builder);
        String referenceTypeRefreshToken = createReferenceTypeRefreshToken(builder);

        logger.tracev("-----   referenceTypeAccessToken = {0}, referenceTypeRefreshToken = {1}", referenceTypeAccessToken, referenceTypeRefreshToken);

        AccessTokenResponse from = builder.build();

        // access token
        logger.trace("----- Binding reference access token");
        bindSelfcontainedTypeToken(from.getToken(), referenceTypeAccessToken);

        // refresh token
        logger.trace("----- Binding reference refresh token");
        bindSelfcontainedTypeToken(from.getRefreshToken(), referenceTypeRefreshToken);

        from.setToken(referenceTypeAccessToken);
        from.setRefreshToken(referenceTypeRefreshToken);
    }

    private void setSelfcontainedTypeTokenBoundWithReferenceTypeToken(String referenceTypeToken, Consumer<String> setSelfcontainedTypeToken, ClientPolicyException exceptionOnInvalidToken) throws ClientPolicyException {

        logger.tracev("-----   referenceTypeToken = {0}", referenceTypeToken);
        String selfcontainedTypeToken = getSelfcontainedTypeToken(referenceTypeToken, exceptionOnInvalidToken);

        logger.tracev("-----   selfcontainedTypeToken = {0}", selfcontainedTypeToken);
        setSelfcontainedTypeToken.accept(selfcontainedTypeToken);
    }
}