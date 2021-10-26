/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.dto;

import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

public class SAMLSSOSessionDTO implements Serializable {

    private static final long serialVersionUID = -412560012894923237L;

    private String httpQueryString;
    private String destination;
    private String relayState;
    private String requestMessageString;
    private String issuer;
    private String issuerQualifier;
    private String requestID;
    private String subject;
    private String relyingPartySessionId;
    private String assertionConsumerURL;
    private String customLoginPage;
    private boolean isIdPInitSSO;
    private SAMLSSOReqValidationResponseDTO validationRespDTO;
    private String sessionId;
    private boolean logoutReq;
    private String tenantDomain;
    private boolean invalidLogout;
    private boolean passiveAuth;
    private boolean forceAuth;
    private boolean isIdPInitSLO;
    private int attributeConsumingServiceIndex = 0;
    private List<SAMLAuthenticationContextClassRefDTO> authenticationContextClassRefList;
    private String requestedAuthnContextComparison;
    private List<ClaimMapping> requestedAttributes;
    private Properties properties;
    private String loggedInTenantDomain;

    public String getHttpQueryString() {
        return httpQueryString;
    }

    public void setHttpQueryString(String httpQueryString) {
        this.httpQueryString = httpQueryString;
    }

    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public String getRelayState() {
        return relayState;
    }

    public void setRelayState(String relayState) {
        this.relayState = relayState;
    }

    public String getRequestMessageString() {
        return requestMessageString;
    }

    public void setRequestMessageString(String requestMessageString) {
        this.requestMessageString = requestMessageString;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getRequestID() {
        return requestID;
    }

    public void setRequestID(String requestID) {
        this.requestID = requestID;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getRelyingPartySessionId() {
        return relyingPartySessionId;
    }

    public void setRelyingPartySessionId(String relyingPartySessionId) {
        this.relyingPartySessionId = relyingPartySessionId;
    }

    public String getAssertionConsumerURL() {
        return assertionConsumerURL;
    }

    public void setAssertionConsumerURL(String assertionConsumerURL) {
        this.assertionConsumerURL = assertionConsumerURL;
    }

    public String getCustomLoginPage() {
        return customLoginPage;
    }

    public void setCustomLoginPage(String customLoginPage) {
        this.customLoginPage = customLoginPage;
    }

    public boolean isIdPInitSSO() {
        return isIdPInitSSO;
    }

    public void setIdPInitSSO(boolean isIdPInitSSO) {
        this.isIdPInitSSO = isIdPInitSSO;
    }

    public SAMLSSOReqValidationResponseDTO getValidationRespDTO() {
        return validationRespDTO;
    }

    public void setValidationRespDTO(
            SAMLSSOReqValidationResponseDTO validationRespDTO) {
        this.validationRespDTO = validationRespDTO;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public boolean isLogoutReq() {
        return logoutReq;
    }

    public void setLogoutReq(boolean logoutReq) {
        this.logoutReq = logoutReq;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public boolean isInvalidLogout() {
        return invalidLogout;
    }

    public void setInvalidLogout(boolean invalidLogout) {
        this.invalidLogout = invalidLogout;
    }

    public boolean isPassiveAuth() {
        return passiveAuth;
    }

    public void setPassiveAuth(boolean passiveAuth) {
        this.passiveAuth = passiveAuth;
    }

    public boolean isForceAuth() {
        return forceAuth;
    }

    public void setForceAuth(boolean forceAuth) {
        this.forceAuth = forceAuth;
    }

    public boolean isIdPInitSLO() {
        return isIdPInitSLO;
    }

    public void setIdPInitSLO(boolean isIdPInitSLO) {
        this.isIdPInitSLO = isIdPInitSLO;
    }

    public int getAttributeConsumingServiceIndex() {
        return attributeConsumingServiceIndex;
    }

    public void setAttributeConsumingServiceIndex(int attributeConsumingServiceIndex) {
        this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
    }

    /**
     * Get list of Authentication Context Class Reference.
     * 
     * @return list of Authentication Context Class Reference
     */
    public List<SAMLAuthenticationContextClassRefDTO> getAuthenticationContextClassRefList() {

        if (authenticationContextClassRefList == null) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(authenticationContextClassRefList);
    }

    /**
     * Set Authentication Context Class Reference.
     *
     * @param authenticationContextClassRefList list of Authentication Context Class Reference
     */
    public void setAuthenticationContextClassRefList(List<SAMLAuthenticationContextClassRefDTO>
                                                             authenticationContextClassRefList) {

        if (this.authenticationContextClassRefList == null) {
            this.authenticationContextClassRefList = authenticationContextClassRefList;
        } else {
            this.authenticationContextClassRefList.addAll(authenticationContextClassRefList);
        }
    }

    /**
     * Add Authentication Context Class Reference.
     *
     * @param authenticationContextClassRefDTO Authentication Context Class Reference
     */
    public void addAuthenticationContextClassRef(
            SAMLAuthenticationContextClassRefDTO authenticationContextClassRefDTO) {

        if (authenticationContextClassRefList == null) {
            authenticationContextClassRefList = new ArrayList<>();
        }
        authenticationContextClassRefList.add(authenticationContextClassRefDTO);
    }

    /**
     * Get requested attributes.
     *
     * @return list of requested attributes
     */
    public List<ClaimMapping> getRequestedAttributes() {

        return requestedAttributes;
    }

    /**
     * Set requested attributes.
     *
     * @param requestedAttributes list of requested attributes
     */
    public void setRequestedAttributes(List<ClaimMapping> requestedAttributes) {

        if (this.requestedAttributes == null) {
            this.requestedAttributes = requestedAttributes;
        } else {
            this.requestedAttributes.addAll(requestedAttributes);
        }
    }

    /**
     * Get Authentication Context Comparison.
     *
     * @return Authentication Context Comparison
     */
    public String getRequestedAuthnContextComparison() {

        return requestedAuthnContextComparison;
    }

    /**
     * Set Authentication Context Comparison.
     *
     * @param requestedAuthnContextComparison Authentication Context Comparison
     */
    public void setRequestedAuthnContextComparison(String requestedAuthnContextComparison) {

        this.requestedAuthnContextComparison = requestedAuthnContextComparison;
    }

    /**
     * Get properties.
     *
     * @return request properties
     */
    public Properties getProperties() {

        if (properties == null) {
            properties = new Properties();
        }
        return properties;
    }

    /**
     * Add a request property.
     *
     * @param key key of the properties entry
     * @param value value of the properties entry
     */
    public void addProperty(String key, String value) {

        properties.put(key, value);
    }

    /**
     * Set properties.
     *
     * @param properties request properties
     */
    public void setProperties(Properties properties) {

        if (this.properties == null) {
            this.properties = new Properties();
        }
        this.properties.putAll(properties);
    }

    /**
     * Get issuer qualifier value.
     *
     * @return issuer qualifier.
     */
    public String getIssuerQualifier() {

        return issuerQualifier;
    }

    /**
     * Set issuer qualifier value.
     *
     * @param issuerQualifier issuer qualifier.
     */
    public void setIssuerQualifier(String issuerQualifier) {

        this.issuerQualifier = issuerQualifier;
    }

    /**
     * Get logged in tenant domain.
     *
     * @return loggedInTenantDomain Logged in tenant domain.
     */
    public String getLoggedInTenantDomain() {

        return loggedInTenantDomain;
    }

    /**
     * Set logged in tenant domain.
     *
     * @param loggedInTenantDomain Logged in tenant domain.
     */
    public void setLoggedInTenantDomain(String loggedInTenantDomain) {

        this.loggedInTenantDomain = loggedInTenantDomain;
    }
}
