/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.os890.cdi.jwt.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import net.minidev.json.JSONObject;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.os890.cdi.jwt.spi.IdentityHolder;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

//simple jwt-handling without encryption -> don't use it in production as it is
@ApplicationScoped
public class AuthenticationManager {
    private String secretToken;

    @Inject
    private TokenExpirationManager expirationManager;

    @Inject
    private IdentityHolder identityHolder;

    @PostConstruct
    public void onPostConstruct() {
        this.secretToken = ConfigResolver.getPropertyValue("jwt_secret");

        if (this.secretToken == null) {
            throw new IllegalArgumentException("key 'jwt_secret' is missing in a config like META-INF/apache-deltaspike.properties");
        }
    }

    public String createNewToken(String email) throws Exception {
        JWSSigner signer = new MACSigner(secretToken);

        JSONObject payload = new JSONObject();
        payload.put("exp", expirationManager.getExpirationTimeInMilliSeconds());
        payload.put("sub", email);

        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS512), new Payload(payload));
        jwsObject.sign(signer);
        String token = jwsObject.serialize();
        return token;
    }

    public void restoreIdentity(String token) throws Exception {
        JWSObject jws = JWSObject.parse(token);

        JWSVerifier verifier = new MACVerifier(secretToken);

        if (jws.verify(verifier)) {
            JSONObject payload = jws.getPayload().toJSONObject();
            Object expirationInMs = payload.get("exp");
            if (expirationInMs instanceof Number) {
                long tokenExpirationInMs = ((Number) expirationInMs).longValue();
                expirationManager.setRestoredExpirationTimeInMs(tokenExpirationInMs);

                if (!expirationManager.isTokenExpired()) {
                    String email = payload.get("sub").toString();
                    identityHolder.setAuthenticatedEMail(email);
                }
            }
        }
    }
}
