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

package org.wso2.carbon.identity.authenticator.inbound.saml2sso.model;

import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * SAML2 SSO Request Validator Config Bean.
 */
public class RequestValidatorConfig implements Serializable {

    private static final long serialVersionUID = 7248171091829064189L;

    private org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig requestValidatorConfig;

    public RequestValidatorConfig(
            org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig requestValidatorConfig) {
        this.requestValidatorConfig = requestValidatorConfig;
    }

    public String getSPEntityId() {
        return (String) this.requestValidatorConfig.getProperties().get
                (SAML2AuthConstants.Config.Name.SP_ENTITY_ID);
    }

    public String getDefaultAssertionConsumerUrl() {
        return (String) this.requestValidatorConfig.getProperties().get(
                SAML2AuthConstants.Config.Name.DEFAULT_ASSERTION_CONSUMER_URL);
    }

    public List<String> getAssertionConsumerUrlList() {
        List<String> assertionConsumerUrlStrings = new ArrayList();
        List assertionConsumerUrls = (List) this.requestValidatorConfig.getProperties().get
                (SAML2AuthConstants.Config.Name.ASSERTION_CONSUMER_URLS);
        if (assertionConsumerUrls == null || assertionConsumerUrls.isEmpty()) {
            return assertionConsumerUrlStrings;
        }
        assertionConsumerUrls.stream().forEach(a -> assertionConsumerUrlStrings.add((String) a));
        return assertionConsumerUrlStrings;
    }

    public boolean isRequireSignatureValidation() {
        return Boolean.parseBoolean(
                (String) this.requestValidatorConfig.getProperties().get(
                        SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED));
    }

    public String getSigningCertificate() {
        return (String) this.requestValidatorConfig.getProperties().get(
                SAML2AuthConstants.Config.Name.SIGNING_CERTIFICATE);
    }

    public boolean sendBackClaimsAlways() {
        return Boolean
                .parseBoolean((String) this.requestValidatorConfig.getProperties().get(
                        SAML2AuthConstants.Config.Name.SEND_CLAIMS_ALWAYS));
    }

    public String getAttributeConsumingServiceIndex() {
        return (String) this.requestValidatorConfig.getProperties().get(
                SAML2AuthConstants.Config.Name.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
    }

    public boolean isIdPInitSSOEnabled() {
        return Boolean.parseBoolean((String) this.requestValidatorConfig.getProperties().get(
                SAML2AuthConstants.Config.Name.IDP_INIT_SSO_ENABLED));
    }

// Need to enable debug logging for inbound.saml2sso during tests to uncomment this
//    @Override
//    public String toString() {
//        final StringBuffer sb = new StringBuffer("RequestValidatorConfig{");
//        sb.append(", spEntityId='").append(getSPEntityId()).append('\'');
//        sb.append(", defaultAssertionConsumerUrl='").append(getDefaultAssertionConsumerUrl()).append('\'');
//        sb.append(", assertionConsumerUrlList=").append(getAssertionConsumerUrlList());
//        sb.append(", requireSignatureValidation=").append(isRequireSignatureValidation());
//        sb.append(", signingCertificate='").append(getSigningCertificate()).append('\'');
//        sb.append(", sendBackClaimsAlways=").append(sendBackClaimsAlways());
//        sb.append(", attributeConsumingServiceIndex='").append(getAttributeConsumingServiceIndex()).append('\'');
//        sb.append(", idPInitSSOEnabled=").append(isIdPInitSSOEnabled());
//        sb.append('}');
//        return sb.toString();
//    }
}
