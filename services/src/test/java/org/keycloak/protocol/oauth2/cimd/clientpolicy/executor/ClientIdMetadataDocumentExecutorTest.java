/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oauth2.cimd.clientpolicy.executor;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

import org.junit.Test;
import org.keycloak.services.clientpolicy.ClientPolicyException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ClientIdMetadataDocumentExecutorTest {

    @Test
    public void trustedDomainMatchingIsCaseInsensitive() {
        ClientIdMetadataDocumentExecutor executor = new ClientIdMetadataDocumentExecutor(null, null);

        assertTrue(executor.checkTrustedDomain("WWW.EXAMPLE.COM", "*.example.com"));
        assertTrue(executor.checkTrustedDomain("LOCALHOST", "localhost"));
    }

    @Test
    public void verifyUriRejectsLoopbackAddressWhenHttpSchemeNotAllowed() throws Exception {
        ClientIdMetadataDocumentExecutor executor = new ClientIdMetadataDocumentExecutor(null, null);
        ClientIdMetadataDocumentExecutor.Configuration configuration = new ClientIdMetadataDocumentExecutor.Configuration();
        configuration.setTrustedDomains(List.of("localhost"));
        configuration.setAllowHttpScheme(false);
        executor.setupConfiguration(configuration);

        ClientPolicyException exception = assertVerifyUriFails(executor, "https://localhost/test");
        assertEquals(AbstractClientIdMetadataDocumentExecutor.ERR_NOTALLOWED_DOMAIN, exception.getErrorDetail());
    }

    @Test
    public void verifyUriAllowsLoopbackAddressWhenHttpSchemeAllowed() throws Exception {
        ClientIdMetadataDocumentExecutor executor = new ClientIdMetadataDocumentExecutor(null, null);
        ClientIdMetadataDocumentExecutor.Configuration configuration = new ClientIdMetadataDocumentExecutor.Configuration();
        configuration.setTrustedDomains(List.of("localhost"));
        configuration.setAllowHttpScheme(true);
        executor.setupConfiguration(configuration);

        invokeVerifyUri(executor, "https://localhost/test");
    }

    private static ClientPolicyException assertVerifyUriFails(ClientIdMetadataDocumentExecutor executor, String uriString) throws Exception {
        try {
            invokeVerifyUri(executor, uriString);
            fail("Expected ClientPolicyException to be thrown");
            return null;
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof ClientPolicyException);
            return (ClientPolicyException) e.getCause();
        }
    }

    private static void invokeVerifyUri(ClientIdMetadataDocumentExecutor executor, String uriString) throws Exception {
        Method method = AbstractClientIdMetadataDocumentExecutor.class.getDeclaredMethod("verifyUri", String.class, AbstractClientIdMetadataDocumentExecutor.ErrorHandler.class);
        method.setAccessible(true);
        method.invoke(executor, uriString, (AbstractClientIdMetadataDocumentExecutor.ErrorHandler) (error, logMessageTemplate) -> {
            throw AbstractClientIdMetadataDocumentExecutor.invalidClientIdMetadata(error);
        });
    }
}
