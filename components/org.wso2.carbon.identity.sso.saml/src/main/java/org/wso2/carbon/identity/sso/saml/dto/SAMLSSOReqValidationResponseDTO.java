/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

public class SAMLSSOReqValidationResponseDTO implements Serializable {

    private static final long serialVersionUID = -2483397754723075495L;

    private boolean isLogOutReq;
    private boolean isValid;
    private boolean doSingleLogout;
    private String issuer;
    private String subject;
    private String assertionConsumerURL;
    private String response;
    private String id;
    private String logoutResponse;
    private String loginPageURL;
    private String rpSessionId;
    private String requestMessageString;
    private String queryString;
    private boolean isPassive;
    private boolean isForceAuthn;
    private String destination;
    private SingleLogoutRequestDTO[] logoutRespDTO;
    private boolean isIdPInitSSO;
    private boolean logoutFromAuthFramework;
    private boolean isIdPInitSLO;
    private String returnToURL;
    private boolean doSignResponse;
    private String signingAlgorithmUri;
    private String digestAlgorithmUri;
    private int attributeConsumingServiceIndex = 0;
    private List<SAMLAuthenticationContextClassRefDTO> authenticationContextClassRefList;
    private String requestedAuthnContextComparison;
    private List<ClaimMapping> requestedAttributes;
    private Properties properties;

    public String getDigestAlgorithmUri() {
        return digestAlgorithmUri;
    }

    public void setDigestAlgorithmUri(String digestAlgorithmUri) {
        if (StringUtils.isNotBlank(digestAlgorithmUri)) {
            this.digestAlgorithmUri = digestAlgorithmUri;
        }
    }

    public String getSigningAlgorithmUri() {
        return signingAlgorithmUri;
    }

    public void setSigningAlgorithmUri(String signingAlgorithmUri) {
        if (StringUtils.isNotBlank(signingAlgorithmUri)) {
            this.signingAlgorithmUri = signingAlgorithmUri;
        }
    }

    public boolean isValid() {
        return isValid;
    }

    public void setValid(boolean valid) {
        isValid = valid;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getAssertionConsumerURL() {
        return assertionConsumerURL;
    }

    public void setAssertionConsumerURL(String assertionConsumerURL) {
        this.assertionConsumerURL = assertionConsumerURL;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public boolean isLogOutReq() {
        return isLogOutReq;
    }

    public void setLogOutReq(boolean logOutReq) {
        isLogOutReq = logOutReq;
    }

    public SingleLogoutRequestDTO[] getLogoutRespDTO() {
        if (logoutRespDTO == null) {
            return new SingleLogoutRequestDTO[0];
        }
        return logoutRespDTO.clone();
    }

    public void setLogoutRespDTO(SingleLogoutRequestDTO[] logoutRespDTO) {
        if (logoutRespDTO == null) {
            this.logoutRespDTO = new SingleLogoutRequestDTO[0];
        } else {
            this.logoutRespDTO = logoutRespDTO.clone();
        }
    }

    public String getLogoutResponse() {
        return logoutResponse;
    }

    public void setLogoutResponse(String logoutResponse) {
        this.logoutResponse = logoutResponse;
    }

    public boolean isDoSingleLogout() {
        return doSingleLogout;
    }

    public void setDoSingleLogout(boolean doSingleLogout) {
        this.doSingleLogout = doSingleLogout;
    }

    public String getLoginPageURL() {
        return loginPageURL;
    }

    public void setLoginPageURL(String loginPageURL) {
        this.loginPageURL = loginPageURL;
    }

    public String getRpSessionId() {
        return rpSessionId;
    }

    public void setRpSessionId(String rpSessionId) {
        this.rpSessionId = rpSessionId;
    }

    /**
     * @return
     */
    public String getRequestMessageString() {
        return requestMessageString;
    }

    /**
     * @param requestMessageString
     */
    public void setRequestMessageString(String requestMessageString) {
        this.requestMessageString = requestMessageString;
    }

    /**
     * @return the queryString
     */
    public String getQueryString() {
        return queryString;
    }

    /**
     * @param queryString the queryString to set
     */
    public void setQueryString(String queryString) {
        this.queryString = queryString;
    }

    /**
     * @return the isPassive attrbute of the AuthnRequest
     */
    public boolean isPassive() {
        return isPassive;
    }

    /**
     * @param isPassive set the AuthnRequest isPassive attribute
     */
    public void setPassive(boolean isPassive) {
        this.isPassive = isPassive;
    }

    /**
     * @return the 'destination' attribute of the SAML request
     */
    public String getDestination() {
        return destination;
    }

    /**
     * @param destination Set the SAML request's 'destination' attribute
     */
    public void setDestination(String destination) {
        this.destination = destination;
    }

    public boolean isIdPInitSSO() {
        return isIdPInitSSO;
    }

    public void setIdPInitSSO(boolean isIdPInitSSO) {
        this.isIdPInitSSO = isIdPInitSSO;
    }

    public boolean isForceAuthn() {
        return isForceAuthn;
    }

    public void setForceAuthn(boolean isForceAuthn) {
        this.isForceAuthn = isForceAuthn;
    }

    public boolean isLogoutFromAuthFramework() {
        return logoutFromAuthFramework;
    }

    public void setLogoutFromAuthFramework(boolean logoutFromAuthFramework) {
        this.logoutFromAuthFramework = logoutFromAuthFramework;
    }

    public boolean isIdPInitSLO() {
        return isIdPInitSLO;
    }

    public void setIdPInitSLO(boolean isIdPInitSLO) {
        this.isIdPInitSLO = isIdPInitSLO;
    }

    public String getReturnToURL() {
        return returnToURL;
    }

    public void setReturnToURL(String returnToURL) {
        this.returnToURL = returnToURL;
    }

    /**
     * @return the doSignResponse
     */
    public boolean isDoSignResponse() {
        return doSignResponse;
    }

    /**
     * @param doSignResponse the doSignResponse to set
     */
    public void setDoSignResponse(boolean doSignResponse) {
        this.doSignResponse = doSignResponse;
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

        if (authenticationContextClassRefList == null) {
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
     * Set properties.
     *
     * @param properties request properties
     */
    public void setProperties(Properties properties) {

        this.properties = properties;
    }
}
