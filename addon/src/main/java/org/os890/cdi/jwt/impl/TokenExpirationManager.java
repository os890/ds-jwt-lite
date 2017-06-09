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

import javax.enterprise.context.RequestScoped;

@RequestScoped
public class TokenExpirationManager {
    protected static int globalExpirationTimeInMilliSeconds = 60 * 60 * 1000; //allows to write mocks for tests
    private static int tokenRenewTimeframeInMilliSeconds;

    static {
        initTokenRenewTimeframe();
    }

    protected int expirationTimeInMilliSeconds = globalExpirationTimeInMilliSeconds;
    private Long restoredExpirationTimeInMs;

    protected static void initTokenRenewTimeframe() {  //allows to write mocks for tests
        tokenRenewTimeframeInMilliSeconds = globalExpirationTimeInMilliSeconds / 3;
    }

    public long getExpirationTimeInMilliSeconds() {
        if (!isNewTokenRequired()) {
            return restoredExpirationTimeInMs;
        }
        return System.currentTimeMillis() + expirationTimeInMilliSeconds;
    }

    public boolean isNewTokenRequired() {
        return !isTokenExpired() && restoredExpirationTimeInMs == null || restoredExpirationTimeInMs - tokenRenewTimeframeInMilliSeconds < System.currentTimeMillis();
    }

    public boolean isTokenExpired() {
        return restoredExpirationTimeInMs != null && restoredExpirationTimeInMs < System.currentTimeMillis();
    }

    public void setRestoredExpirationTimeInMs(long restoredExpirationTimeInMs) {
        this.restoredExpirationTimeInMs = restoredExpirationTimeInMs;
    }
}
