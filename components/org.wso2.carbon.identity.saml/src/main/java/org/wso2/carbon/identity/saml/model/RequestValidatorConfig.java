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

package org.wso2.carbon.identity.saml.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * SAML2 SSO Request Validator Config Bean.
 */
public class RequestValidatorConfig implements Serializable {

    private static final long serialVersionUID = 1926448600042806841L;
    private org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig requestValidatorConfig;

    public RequestValidatorConfig(
            org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig requestValidatorConfig) {
        this.requestValidatorConfig = requestValidatorConfig;
    }

    public String getSPEntityId() {
        return (String) this.requestValidatorConfig.getProperties().get("issuer");
    }

    public String getDefaultAssertionConsumerUrl() {
        return (String) this.requestValidatorConfig.getProperties().get("defaultAssertionConsumerUrl");
    }

    public List<String> getAssertionConsumerUrlList() {
        List<String> assertionConsumerUrlStrings = new ArrayList();
        List assertionConsumerUrls = (List) this.requestValidatorConfig.getProperties().get
                ("assertionConsumerUrls");
        if (assertionConsumerUrls == null || assertionConsumerUrls.isEmpty()){
            return assertionConsumerUrlStrings;
        }
        assertionConsumerUrls.stream().forEach(a -> assertionConsumerUrlStrings.add((String) a));
        return assertionConsumerUrlStrings;
    }

    public boolean isRequireSignatureValidation() {
        return Boolean.parseBoolean(
                (String) this.requestValidatorConfig.getProperties().get("doValidateSignatureInRequests"));
    }

    public String getSigningCertificate() {
        return (String) this.requestValidatorConfig.getProperties().get("certificate");
    }

    public boolean sendBackClaimsAlways() {
        return Boolean
                .parseBoolean((String) this.requestValidatorConfig.getProperties().get("enableAttributesByDefault"));
    }

    public String getAttributeConsumingServiceIndex() {
        return (String) this.requestValidatorConfig.getProperties().get("attributeConsumingServiceIndex");
    }

    public boolean isIdPInitSSOEnabled() {
        return Boolean.parseBoolean((String) this.requestValidatorConfig.getProperties().get("idPInitSSOEnabled"));
    }
}
