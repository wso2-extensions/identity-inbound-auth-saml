/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.inbound.saml2sso.internal;

import org.wso2.carbon.identity.authenticator.inbound.saml2sso.response.SAMLResponseBuilder;
import org.wso2.carbon.identity.gateway.service.GatewayClaimResolverService;

/**
 * SAML2 SSO Inbound Authenticator Component Data Holder.
 */
public class SAML2InboundAuthDataHolder {

    private static volatile SAML2InboundAuthDataHolder instance = new SAML2InboundAuthDataHolder();
    private GatewayClaimResolverService gatewayClaimResolverService = null;
    private SAMLResponseBuilder samlResponseBuilder = new SAMLResponseBuilder();

    private SAML2InboundAuthDataHolder() {

    }

    public static SAML2InboundAuthDataHolder getInstance() {
        return instance;
    }

    public GatewayClaimResolverService getGatewayClaimResolverService() {
        return gatewayClaimResolverService;
    }

    public SAMLResponseBuilder getSamlResponseBuilder() {
        return samlResponseBuilder;
    }

    public void setGatewayClaimResolverService(GatewayClaimResolverService gatewayClaimResolverService) {
        this.gatewayClaimResolverService = gatewayClaimResolverService;
    }

    public void setSAMLResponseBuilder(SAMLResponseBuilder samlResponseBuilder) {
        this.samlResponseBuilder = samlResponseBuilder;
    }
}
