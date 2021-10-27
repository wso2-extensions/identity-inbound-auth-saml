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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationContextProperty;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class SAMLSSOAuthnReqDTO implements Serializable {

    private static final long serialVersionUID = -8883458443469019318L;

    private AuthenticatedUser user;
    private String password;
    private String issuer;
    private String issuerQualifier;
    private String subject;
    private String assertionConsumerURL;
    private String[] assertionConsumerURLs;
    private String id;
    private String claim;
    private String audience;
    private String recipient;
    private String nameIDFormat;
    private String sloResponseURL;
    private String sloRequestURL;
    private String loginPageURL;
    private String rpSessionId;
    private String requestMessageString;
    private String queryString;
    private String destination;
    private String[] requestedClaims;
    private String[] requestedAudiences;
    private String[] requestedRecipients;
    private boolean doSingleLogout;
    private boolean doFrontChannelLogout;
    private String frontChannelLogoutBinding;
    private boolean doSignResponse;
    private boolean doSignAssertions;
    private boolean isStratosDeployment = false;
    private int attributeConsumingServiceIndex = 0;
    private String nameIdClaimUri;
    private boolean idPInitSSOEnabled;
    private boolean idPInitSLOEnabled;
    private String[] idpInitSLOReturnToURLs;
    private boolean doEnableEncryptedAssertion;
    private boolean doValidateSignatureInRequests;
    private Map<String, String> claimMapping = null;
    private String tenantDomain;
    private String certAlias;
    private String signingAlgorithmUri;
    private String digestAlgorithmUri;
    private String assertionEncryptionAlgorithmUri;
    private String keyEncryptionAlgorithmUri;
    private boolean isAssertionQueryRequestProfileEnabled;
    private boolean enableSAML2ArtifactBinding;
    private Map<String, List<AuthenticationContextProperty>> idpAuthenticationContextProperties;
    private List<SAMLAuthenticationContextClassRefDTO> authenticationContextClassRefList;
    private String requestedAuthnContextComparison;
    private List<ClaimMapping> requestedAttributesList;
    private Properties properties;
    private boolean doValidateSignatureInArtifactResolve;
    private boolean samlECPEnabled;
    private long createdTimeStamp;
    private String loggedInTenantDomain;

    public void setDoValidateSignatureInArtifactResolve(boolean doValidateSignatureInArtifactResolve) {

        this.doValidateSignatureInArtifactResolve = doValidateSignatureInArtifactResolve;
    }

    public boolean isDoValidateSignatureInArtifactResolve() {

        return doValidateSignatureInArtifactResolve;
    }

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

    public String getAssertionEncryptionAlgorithmUri() {
        return assertionEncryptionAlgorithmUri;
    }

    public void setAssertionEncryptionAlgorithmUri(String assertionEncryptionAlgorithmUri) {
        if (StringUtils.isNotBlank(assertionEncryptionAlgorithmUri)) {
            this.assertionEncryptionAlgorithmUri = assertionEncryptionAlgorithmUri;
        }
    }

    public String getKeyEncryptionAlgorithmUri() {
        return keyEncryptionAlgorithmUri;
    }

    public void setKeyEncryptionAlgorithmUri(String keyEncryptionAlgorithmUri) {
        if (StringUtils.isNotBlank(keyEncryptionAlgorithmUri)) {
            this.keyEncryptionAlgorithmUri = keyEncryptionAlgorithmUri;
        }
    }

    public String getNameIdClaimUri() {
        return nameIdClaimUri;
    }

    public void setNameIdClaimUri(String nameIdClaimUri) {
        this.nameIdClaimUri = nameIdClaimUri;
    }

    public int getAttributeConsumingServiceIndex() {
        return attributeConsumingServiceIndex;
    }

    public void setAttributeConsumingServiceIndex(
            int attributeConsumingServiceIndex) {
        this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
    }

    public String getCertAlias() {
        return certAlias;
    }

    public void setCertAlias(String certAlias) {
        this.certAlias = certAlias;
    }

    public AuthenticatedUser getUser() {
        return user;
    }

    public void setUser(AuthenticatedUser user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getIssuer() {
        if (issuer.contains("@")) {
            String[] splitIssuer = issuer.split("@");
            return splitIssuer[0];
        }
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getIssuerWithDomain() {
        return issuer;
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

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getNameIDFormat() {
        return nameIDFormat;
    }

    public void setNameIDFormat(String nameIDFormat) {
        this.nameIDFormat = nameIDFormat;
    }

    public String getClaim() {
        return claim;
    }

    public void setClaim(String claim) {
        this.claim = claim;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getRecipient() {
        return recipient;
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public String getSloResponseURL() {
        return sloResponseURL;
    }

    public void setSloResponseURL(String sloResponseURL) {
        this.sloResponseURL = sloResponseURL;
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

    public boolean getDoSignAssertions() {
        return doSignAssertions;
    }

    public void setDoSignAssertions(boolean doSignAssertions) {
        this.doSignAssertions = doSignAssertions;
    }

    public boolean isDoFrontChannelLogout() {

        return doFrontChannelLogout;
    }

    public void setDoFrontChannelLogout(boolean doFrontChannelLogout) {

        this.doFrontChannelLogout = doFrontChannelLogout;
    }

    public String getFrontChannelLogoutBinding() {

        return frontChannelLogoutBinding;
    }

    public void setFrontChannelLogoutBinding(String frontChannelLogoutBinding) {

        this.frontChannelLogoutBinding = frontChannelLogoutBinding;
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

    public String[] getRequestedClaims() {
        if (requestedClaims == null) {
            return new String[0];
        }
        return requestedClaims.clone();
    }

    public void setRequestedClaims(String[] requestedClaims) {
        if (requestedClaims == null) {
            this.requestedClaims = new String[0];
        } else {
            this.requestedClaims = requestedClaims.clone();
        }
    }

    public String[] getRequestedAudiences() {
        if (requestedAudiences == null) {
            return new String[0];
        }
        return requestedAudiences.clone();
    }

    public void setRequestedAudiences(String[] requestedAudiences) {
        if (requestedAudiences == null) {
            this.requestedAudiences = new String[0];
        } else {
            this.requestedAudiences = requestedAudiences.clone();
        }
    }

    public String[] getRequestedRecipients() {
        if (requestedRecipients == null) {
            return new String[0];
        }
        return requestedRecipients.clone();
    }

    public void setRequestedRecipients(String[] requestedRecipients) {
        if (requestedRecipients == null) {
            this.requestedRecipients = new String[0];
        } else {
            this.requestedRecipients = requestedRecipients.clone();
        }
    }

    public boolean isStratosDeployment() {
        return isStratosDeployment;
    }

    public void setStratosDeployment(boolean isStratosDeployment) {
        this.isStratosDeployment = isStratosDeployment;
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

    public boolean isIdPInitSSOEnabled() {
        return idPInitSSOEnabled;
    }

    public void setIdPInitSSOEnabled(boolean isIdPInitSSO) {
        this.idPInitSSOEnabled = isIdPInitSSO;
    }

    public boolean isDoEnableEncryptedAssertion() {
        return doEnableEncryptedAssertion;
    }

    public void setDoEnableEncryptedAssertion(boolean doEnableEncryptedAssertion) {
        this.doEnableEncryptedAssertion = doEnableEncryptedAssertion;
    }

    public boolean isDoValidateSignatureInRequests() {
        return doValidateSignatureInRequests;
    }

    public void setDoValidateSignatureInRequests(
            boolean doValidateSignatureInRequests) {
        this.doValidateSignatureInRequests = doValidateSignatureInRequests;
    }

    public Map<String, String> getClaimMapping() {
        return claimMapping;
    }

    public void setClaimMapping(Map<String, String> claimMapping) {
        this.claimMapping = claimMapping;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public boolean isIdPInitSLOEnabled() {
        return idPInitSLOEnabled;
    }

    public void setIdPInitSLOEnabled(boolean idPInitSLOEnabled) {
        this.idPInitSLOEnabled = idPInitSLOEnabled;
    }

    public String[] getAssertionConsumerURLs() {
        return assertionConsumerURLs;
    }

    public void setAssertionConsumerURLs(String[] assertionConsumerURLs) {
        this.assertionConsumerURLs = assertionConsumerURLs;
    }

    public String[] getIdpInitSLOReturnToURLs() {
        return idpInitSLOReturnToURLs;
    }

    public void setIdpInitSLOReturnToURLs(String[] idpInitSLOReturnToURLs) {
        this.idpInitSLOReturnToURLs = idpInitSLOReturnToURLs;
    }

    public String getSloRequestURL() {
        return sloRequestURL;
    }

    public void setSloRequestURL(String sloRequestURL) {
        this.sloRequestURL = sloRequestURL;
    }

    public void setAssertionQueryRequestProfileEnabled(boolean assertionQueryRequestProfileEnabled) {
        this.isAssertionQueryRequestProfileEnabled = assertionQueryRequestProfileEnabled;
    }

    public boolean isAssertionQueryRequestProfileEnabled() {
        return this.isAssertionQueryRequestProfileEnabled;
    }

    public void setEnableSAML2ArtifactBinding(boolean enableSAML2ArtifactBinding) {

        this.enableSAML2ArtifactBinding = enableSAML2ArtifactBinding;
    }

    public boolean isSAML2ArtifactBindingEnabled() {

        return enableSAML2ArtifactBinding;
    }

    public boolean isSamlECPEnabled(){
        return samlECPEnabled;
    }

    public void setSamlECPEnabled(boolean samlECPEnabled){
        this.samlECPEnabled = samlECPEnabled;
    }

    public Map<String, List<AuthenticationContextProperty>> getIdpAuthenticationContextProperties() {

        if (idpAuthenticationContextProperties == null) {
            idpAuthenticationContextProperties = new HashMap<>();
        }
        return idpAuthenticationContextProperties;
    }

    public void setIdpAuthenticationContextProperties(Map<String, List<AuthenticationContextProperty>>
                                                              idpAuthenticationContextProperties) {

        this.idpAuthenticationContextProperties = idpAuthenticationContextProperties;
    }

    public void addIdpAuthenticationContextProperty(String propertyName, AuthenticationContextProperty
            authenticationContextProperty) {

        if (idpAuthenticationContextProperties == null) {
            idpAuthenticationContextProperties = new HashMap<>();
        }

        List<AuthenticationContextProperty> authenticationContextProperties;
        if (idpAuthenticationContextProperties.get(propertyName) == null) {
            authenticationContextProperties = new ArrayList<>();
            idpAuthenticationContextProperties.put(propertyName, authenticationContextProperties);
        } else {
            authenticationContextProperties = idpAuthenticationContextProperties.get(propertyName);
        }
        authenticationContextProperties.add(authenticationContextProperty);
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
     * @param authenticationContextClassRefs list of Authentication Context Class Reference
     */
    public void setAuthenticationContextClassRefList(List<SAMLAuthenticationContextClassRefDTO>
                                                             authenticationContextClassRefs) {

        if (authenticationContextClassRefList == null) {
            authenticationContextClassRefList = authenticationContextClassRefs;
        } else {
            authenticationContextClassRefList.addAll(authenticationContextClassRefs);
        }
    }

    /**
     * Add Authentication Context Class Reference.
     *
     * @param authenticationContextClassRefs Authentication Context Class Reference
     */
    public void addAuthenticationContextClassRef(
            SAMLAuthenticationContextClassRefDTO authenticationContextClassRefs) {

        if (authenticationContextClassRefList == null) {
            authenticationContextClassRefList = new ArrayList<>();
        }
        authenticationContextClassRefList.add(authenticationContextClassRefs);
    }

    /**
     * Get Requested Attributes.
     *
     * @return list of requested attributes
     */
    public List<ClaimMapping> getRequestedAttributes() {

        return requestedAttributesList;
    }

    /**
     * Set Requested Attributes.
     *
     * @param requestedAttributes list of requested attributes
     */
    public void setRequestedAttributes(List<ClaimMapping> requestedAttributes) {

        if (requestedAttributesList == null) {
            requestedAttributesList = requestedAttributes;
        } else {
            requestedAttributesList.addAll(requestedAttributes);
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
     * @param authnContextComparison Authentication Context Comparison
     */
    public void setRequestedAuthnContextComparison(String authnContextComparison) {

        requestedAuthnContextComparison = authnContextComparison;
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
     * Get a property.
     *
     * @return request property
     */
    public String getProperty(String propertyKey) {

        String propertyValue = null;
        if (properties != null) {
            propertyValue = (String) properties.get(propertyKey);
        }

        return propertyValue;
    }

    /**
     * Add a request property.
     *
     * @param key key of the properties entry
     * @param value value of the properties entry
     */
    public void addProperty(String key, String value) {

        if (this.properties == null) {
            this.properties = new Properties();
        }
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

    public long getCreatedTimeStamp() {
        return createdTimeStamp;
    }

    public void setCreatedTimeStamp(long createdTimeStamp) {
        this.createdTimeStamp = createdTimeStamp;
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
     * Get login tenant domain.
     *
     * @return loginTenantDomain login tenant domain.
     */
    public String getLoggedInTenantDomain() {

        return loggedInTenantDomain;
    }

    /**
     * Set login tenant domain.
     *
     * @param loggedInTenantDomain login tenant domain.
     */
    public void setLoggedInTenantDomain(String loggedInTenantDomain) {

        this.loggedInTenantDomain = loggedInTenantDomain;
    }
}
