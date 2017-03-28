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

package org.wso2.carbon.identity.authenticator.inbound.saml2sso.bean;

import org.wso2.carbon.identity.authenticator.inbound.saml2sso.model.RequestValidatorConfig;
import org.wso2.carbon.identity.authenticator.inbound.saml2sso.model.ResponseBuilderConfig;
import org.wso2.carbon.identity.authenticator.inbound.saml2sso.request.IdPInitRequest;
import org.wso2.carbon.identity.authenticator.inbound.saml2sso.request.SAML2SSORequest;

import java.io.Serializable;
import java.util.Map;

/**
 * MessageContext specific to Inbound SAML2 SSO.
 */
public class SAML2SSOContext extends org.wso2.carbon.identity.common.base.message.MessageContext {

    private static final long serialVersionUID = -2615276176538577583L;

    private String name;
    private String id;
    private String spEntityId;
    private String assertionConsumerUrl;
    private String destination;
    private String subject;
    private int attributeConsumingServiceIndex;
    private boolean isPassive;
    private boolean isForce;
    private SAML2SSORequest request;

    private RequestValidatorConfig requestValidatorConfig;
    private ResponseBuilderConfig responseBuilderConfig;

    public SAML2SSOContext(Map<Serializable, Serializable> parameters) {
        super(parameters);
    }

    public SAML2SSORequest getRequest() {
        return request;
    }

    public void setRequest(SAML2SSORequest request) {
        this.request = request;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getId() {
        if (!isIdpInitSSO()) {
            return this.id;
        }
        return null;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSPEntityId() {
        return spEntityId;
    }

    public void setSPEntityId(String spEntityId) {
        this.spEntityId = spEntityId;
    }

    public String getAssertionConsumerURL() {
        return this.assertionConsumerUrl;
    }

    public void setAssertionConsumerUrl(String assertionConsumerUrl) {
        this.assertionConsumerUrl = assertionConsumerUrl;
    }

    public String getDestination() {
        return this.destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public int getAttributeConsumingServiceIndex() {
        return attributeConsumingServiceIndex;
    }

    public void setAttributeConsumingServiceIndex(int attributeConsumingServiceIndex) {
        this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
    }

    public boolean isPassive() {
        return this.isPassive;
    }

    public void setPassive(boolean isPassive) {
        this.isPassive = isPassive;
    }

    public boolean isForce() {
        return this.isForce;
    }

    public void setForce(boolean isForce) {
        this.isForce = isForce;
    }

    public String getRelayState() {
        return this.getRequest().getRelayState();
    }

    public boolean isIdpInitSSO() {
        return this.getRequest() instanceof IdPInitRequest;
    }

    public String getIssuerWithDomain() {
        return this.spEntityId;
    }

    public ResponseBuilderConfig getResponseBuilderConfig() {
        return responseBuilderConfig;
    }

    public void setResponseBuilderConfig(ResponseBuilderConfig responseBuilderConfig) {
        this.responseBuilderConfig = responseBuilderConfig;
    }

    public RequestValidatorConfig getRequestValidatorConfig() {
        return requestValidatorConfig;
    }

    public void setRequestValidatorConfig(RequestValidatorConfig requestValidatorConfig) {
        this.requestValidatorConfig = requestValidatorConfig;
    }

// Need to enable debug logging for inbound.saml2sso during tests to uncomment this
//    @Override
//    public String toString() {
//        final StringBuffer sb = new StringBuffer("SAML2SSOContext{");
//        sb.append("name='").append(name).append('\'');
//        sb.append(", id='").append(id).append('\'');
//        sb.append(", spEntityId='").append(spEntityId).append('\'');
//        sb.append(", assertionConsumerUrl='").append(assertionConsumerUrl).append('\'');
//        sb.append(", destination='").append(destination).append('\'');
//        sb.append(", subject='").append(subject).append('\'');
//        sb.append(", attributeConsumingServiceIndex=").append(attributeConsumingServiceIndex);
//        sb.append(", isPassive=").append(isPassive);
//        sb.append(", isForce=").append(isForce);
//        sb.append(", request=").append(request);
//        sb.append(", requestValidatorConfig=").append(requestValidatorConfig);
//        sb.append(", responseBuilderConfig=").append(responseBuilderConfig);
//        sb.append('}');
//        return sb.toString();
//    }
}
