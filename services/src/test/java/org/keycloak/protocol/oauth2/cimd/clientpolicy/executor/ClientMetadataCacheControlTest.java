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

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ClientMetadataCacheControlTest {

    @Test
    public void shouldClampMaxAgeToConfiguredBounds() {
        AbstractClientIdMetadataDocumentExecutor.ClientMetadataCacheControl cacheControl =
                new AbstractClientIdMetadataDocumentExecutor.ClientMetadataCacheControl("max-age=10", 20, 100);

        assertTrue(cacheControl.isMaxAge());
        assertEquals(20, cacheControl.getMaxAgeValue());
    }

    @Test
    public void shouldIgnoreDuplicatedMaxAgeDirective() {
        AbstractClientIdMetadataDocumentExecutor.ClientMetadataCacheControl cacheControl =
                new AbstractClientIdMetadataDocumentExecutor.ClientMetadataCacheControl("max-age=10,max-age=30", 0, 100);

        assertFalse(cacheControl.isMaxAge());
        assertEquals(-1, cacheControl.getMaxAgeValue());
    }

    @Test
    public void shouldHandleNoCacheAndSMaxAgeDirectives() {
        AbstractClientIdMetadataDocumentExecutor.ClientMetadataCacheControl cacheControl =
                new AbstractClientIdMetadataDocumentExecutor.ClientMetadataCacheControl("no-cache,s-maxage=30", 5, 100);

        assertTrue(cacheControl.isNoCache());
        assertTrue(cacheControl.isSmaxAge());
        assertEquals(30, cacheControl.getSmaxAgeValue());
    }
}
