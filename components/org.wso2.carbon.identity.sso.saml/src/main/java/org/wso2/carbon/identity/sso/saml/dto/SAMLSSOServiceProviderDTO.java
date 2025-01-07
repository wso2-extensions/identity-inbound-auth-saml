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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonTypeName;
import org.apache.axis2.databinding.annotation.IgnoreNullElement;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.model.InboundConfigurationProtocol;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;

import java.io.Serializable;
import java.util.Map;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 * This class is used to store the SAML SSO Service Provider related information.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "samlssoServiceProviderDTO")
@JsonTypeName("samlssoServiceProviderDTO")
public class SAMLSSOServiceProviderDTO extends InboundConfigurationProtocol implements Serializable {

    private static final long serialVersionUID = -7633935958583257097L;

    private String issuer;
    private String issuerQualifier;
    @XmlElementWrapper(name = "assertionConsumerUrls")
    @XmlElement(name = "assertionConsumerUrl")
    private String[] assertionConsumerUrls;
    private String defaultAssertionConsumerUrl;
    private String assertionConsumerUrl;
    private String certAlias;
    private String certificateContent;
    private String sloResponseURL;
    private String sloRequestURL;
    private String loginPageURL;
    private String attributeConsumingServiceIndex;
    private String frontChannelLogoutBinding;
    private boolean doSingleLogout;
    private boolean doSignAssertions;
    private boolean doSignResponse;
    private boolean doFrontChannelLogout;
    @XmlElementWrapper(name = "requestedClaims")
    @XmlElement(name = "requestedClaim")
    private String[] requestedClaims;
    @XmlElementWrapper(name = "requestedAudiences")
    @XmlElement(name = "requestedAudience")
    private String[] requestedAudiences;
    @XmlElementWrapper(name = "requestedRecipients")
    @XmlElement(name = "requestedRecipient")
    private String[] requestedRecipients;
    private boolean enableAttributeProfile;
    private String attributeNameFormat;
    private boolean isAssertionQueryRequestProfileEnabled;
    private String supportedAssertionQueryRequestTypes;
    private boolean enableAttributesByDefault;
    private String nameIdClaimUri;
    private String nameIDFormat;
    private boolean idPInitSSOEnabled;
    private boolean idPInitSLOEnabled;
    @XmlElementWrapper(name = "idpInitSLOReturnToURLs")
    @XmlElement(name = "idpInitSLOReturnToURL")
    private String[] idpInitSLOReturnToURLs;
    private boolean doEnableEncryptedAssertion;
    private boolean doValidateSignatureInRequests;
    private String signingAlgorithmURI;
    private String digestAlgorithmURI;
    private String assertionEncryptionAlgorithmURI;
    private String keyEncryptionAlgorithmURI;
    private boolean enableSAML2ArtifactBinding;
    private boolean doValidateSignatureInArtifactResolve;
    private boolean samlECP;
    private  String idpEntityIDAlias;

    @IgnoreNullElement
    @XmlTransient
    @JsonIgnore
    private String auditLogData;

    public void setDoValidateSignatureInArtifactResolve(boolean doValidateSignatureInArtifactResolve) {

        this.doValidateSignatureInArtifactResolve = doValidateSignatureInArtifactResolve;
    }

    public boolean isDoValidateSignatureInArtifactResolve() {

        return doValidateSignatureInArtifactResolve;
    }

    public void setEnableSAML2ArtifactBinding(boolean enableSAML2ArtifactBinding) {

        this.enableSAML2ArtifactBinding = enableSAML2ArtifactBinding;
    }

    public boolean isEnableSAML2ArtifactBinding() {

        return enableSAML2ArtifactBinding;
    }

    public SAMLSSOServiceProviderDTO() {
        signingAlgorithmURI = IdentityApplicationManagementUtil.getSigningAlgoURIByConfig();
        digestAlgorithmURI = IdentityApplicationManagementUtil.getDigestAlgoURIByConfig();
        assertionEncryptionAlgorithmURI = IdentityApplicationManagementUtil
                .getAssertionEncryptionAlgorithmURIByConfig();
        keyEncryptionAlgorithmURI = IdentityApplicationManagementUtil.getKeyEncryptionAlgorithmURIByConfig();
    }

    public String getSigningAlgorithmURI() {
        return signingAlgorithmURI;
    }

    public void setSigningAlgorithmURI(String signingAlgorithmURI) {
        if (StringUtils.isNotBlank(signingAlgorithmURI)) {
            this.signingAlgorithmURI = signingAlgorithmURI;
        }
    }

    public String getDigestAlgorithmURI() {
        return digestAlgorithmURI;
    }

    public void setDigestAlgorithmURI(String digestAlgorithmURI) {
        if (StringUtils.isNotBlank(digestAlgorithmURI)) {
            this.digestAlgorithmURI = digestAlgorithmURI;
        }
    }

    public String getAssertionEncryptionAlgorithmURI() {
        return assertionEncryptionAlgorithmURI;
    }

    public void setAssertionEncryptionAlgorithmURI(String assertionEncryptionAlgorithmURI) {
        if (StringUtils.isNotBlank(assertionEncryptionAlgorithmURI)) {
            this.assertionEncryptionAlgorithmURI = assertionEncryptionAlgorithmURI;
        }
    }

    public String getKeyEncryptionAlgorithmURI() {
        return keyEncryptionAlgorithmURI;
    }

    public void setKeyEncryptionAlgorithmURI(String keyEncryptionAlgorithmURI) {
        if (StringUtils.isNotBlank(keyEncryptionAlgorithmURI)) {
            this.keyEncryptionAlgorithmURI = keyEncryptionAlgorithmURI;
        }
    }

    public String getNameIDFormat() {
        return nameIDFormat;
    }

    public void setNameIDFormat(String nameIDFormat) {
        this.nameIDFormat = nameIDFormat;
    }

    public String getNameIdClaimUri() {
        return nameIdClaimUri;
    }

    public void setNameIdClaimUri(String nameIdClaimUri) {
        this.nameIdClaimUri = nameIdClaimUri;
    }

    public boolean isEnableAttributeProfile() {
        return enableAttributeProfile;
    }

    public void setEnableAttributeProfile(boolean enableAttributeProfile) {
        this.enableAttributeProfile = enableAttributeProfile;
    }

    public boolean isAssertionQueryRequestProfileEnabled() {
        return isAssertionQueryRequestProfileEnabled;
    }

    public void setAssertionQueryRequestProfileEnabled(boolean isAssertionQueryRequestProfileEnabled) {
        this.isAssertionQueryRequestProfileEnabled = isAssertionQueryRequestProfileEnabled;
    }

    public String getSupportedAssertionQueryRequestTypes() {
        return supportedAssertionQueryRequestTypes;
    }

    public void setSupportedAssertionQueryRequestTypes(String supportedAssertionQueryRequestTypes) {
        this.supportedAssertionQueryRequestTypes = supportedAssertionQueryRequestTypes;
    }

    public boolean isEnableAttributesByDefault() {
        return enableAttributesByDefault;
    }

    public void setEnableAttributesByDefault(boolean enableAttributesByDefault) {
        this.enableAttributesByDefault = enableAttributesByDefault;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAssertionConsumerUrl() {
        return assertionConsumerUrl;
    }

    public void setAssertionConsumerUrl(String assertionConsumerUrl) {
        this.assertionConsumerUrl = assertionConsumerUrl;
    }

    public String getCertAlias() {
        return certAlias;
    }

    public void setCertAlias(String certAlias) {
        this.certAlias = certAlias;
    }

    public boolean isDoSingleLogout() {
        return doSingleLogout;
    }

    public void setDoSingleLogout(boolean doSingleLogout) {
        this.doSingleLogout = doSingleLogout;
    }

    public String getSloResponseURL() {
        return sloResponseURL;
    }

    public void setSloResponseURL(String logoutURL) {
        this.sloResponseURL = logoutURL;
    }

    public String getLoginPageURL() {
        return loginPageURL;
    }

    public void setLoginPageURL(String loginPageURL) {
        this.loginPageURL = loginPageURL;
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
    public boolean isDoSignAssertions() {
        return doSignAssertions;
    }

    /**
     * @param doSignAssertions
     */
    public void setDoSignAssertions(boolean doSignAssertions) {
        this.doSignAssertions = doSignAssertions;
    }

    public String getAttributeConsumingServiceIndex() {
        return attributeConsumingServiceIndex;
    }

    public void setAttributeConsumingServiceIndex(String attributeConsumingServiceIndex) {
        this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
    }

    /**
     * @return the requestedClaims
     */
    public String[] getRequestedClaims() {

        if (requestedClaims == null) {
            return new String[0];
        }
        return requestedClaims.clone();
    }

    /**
     * @param requestedClaims the requestedClaims to set
     */
    public void setRequestedClaims(String[] requestedClaims) {

        if (requestedClaims == null) {
            requestedClaims = new String[0];
        }
        this.requestedClaims = requestedClaims.clone();
    }

    /**
     * @return the requestedAudiences
     */
    public String[] getRequestedAudiences() {

        if (requestedAudiences == null) {
            return new String[0];
        }
        return requestedAudiences.clone();
    }

    /**
     * @param requestedAudiences the requestedAudiences to set
     */
    public void setRequestedAudiences(String[] requestedAudiences) {

        if (requestedAudiences == null) {
            requestedAudiences = new String[0];
        }
        this.requestedAudiences = requestedAudiences.clone();
    }

    /**
     * @return the requestedRecipients
     */
    public String[] getRequestedRecipients() {

        if (requestedRecipients == null) {
            return new String[0];
        }
        return requestedRecipients.clone();
    }

    /**
     * @param requestedRecipients the requestedRecipients to set
     */
    public void setRequestedRecipients(String[] requestedRecipients) {

        if (requestedRecipients == null) {
            requestedRecipients = new String[0];
        }
        this.requestedRecipients = requestedRecipients;
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

    public boolean isIdPInitSSOEnabled() {
        return idPInitSSOEnabled;
    }

    public void setIdPInitSSOEnabled(boolean idPInitSSOEnabled) {
        this.idPInitSSOEnabled = idPInitSSOEnabled;
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

    public void setDoValidateSignatureInRequests(boolean doValidateSignatureInRequests) {
        this.doValidateSignatureInRequests = doValidateSignatureInRequests;
    }

    public String[] getAssertionConsumerUrls() {

        if (assertionConsumerUrls == null) {
            return new String[0];
        }
        return assertionConsumerUrls.clone();
    }

    public void setAssertionConsumerUrls(String[] assertionConsumerUrls) {
        this.assertionConsumerUrls = assertionConsumerUrls;
    }

    public String getDefaultAssertionConsumerUrl() {
        return defaultAssertionConsumerUrl;
    }

    public void setDefaultAssertionConsumerUrl(String defaultAssertionConsumerUrl) {
        this.defaultAssertionConsumerUrl = defaultAssertionConsumerUrl;
    }

    public String getSloRequestURL() {
        return sloRequestURL;
    }

    public void setSloRequestURL(String sloRequestURL) {
        this.sloRequestURL = sloRequestURL;
    }

    public boolean isIdPInitSLOEnabled() {
        return idPInitSLOEnabled;
    }

    public void setIdPInitSLOEnabled(boolean idPInitSLOEnabled) {
        this.idPInitSLOEnabled = idPInitSLOEnabled;
    }

    public String[] getIdpInitSLOReturnToURLs() {

        if (idpInitSLOReturnToURLs == null) {
            return ArrayUtils.EMPTY_STRING_ARRAY;
        }
        return idpInitSLOReturnToURLs.clone();
    }

    public void setIdpInitSLOReturnToURLs(String[] idpInitSLOReturnToURLs) {

        if (idpInitSLOReturnToURLs != null) {
            this.idpInitSLOReturnToURLs = idpInitSLOReturnToURLs.clone();
        } else {
            this.idpInitSLOReturnToURLs = null;
        }
    }

    public void setCertificateContent(String certificateContent) {

        this.certificateContent = certificateContent;
    }

    public String getCertificateContent() {

        return certificateContent;
    }

    public boolean isSamlECP() {
        return samlECP;
    }

    public void setSamlECP(boolean samlECP) {
        this.samlECP = samlECP;
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
     * Get idp entity id alias value.
     *
     * @return
     */
    public String getIdpEntityIDAlias() {

        return idpEntityIDAlias;
    }

    /**
     * Set idp entity id alias value.
     *
     * @param idpEntityIDAlias
     */
    public void setIdpEntityIDAlias(String idpEntityIDAlias) {

        this.idpEntityIDAlias = idpEntityIDAlias;
    }
    
    /**
     * Get audit log data.
     * @return A map of audit log data.
     */
    public String getAuditLogData() {
        
        return auditLogData;
    }
    
    /**
     * Set audit log data.
     * @param auditLogData A map of audit log data.
     */
    public void setAuditLogData(String auditLogData) {
        
        this.auditLogData = auditLogData;
    }

    public void setAttributeNameFormat(String attributeNameFormat) {

        this.attributeNameFormat = attributeNameFormat;
    }

    public String getAttributeNameFormat() {

        return attributeNameFormat;
    }
}
