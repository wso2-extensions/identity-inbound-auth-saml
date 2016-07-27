/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.sso.samlnew.configs;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;

public class SAMLAuthenticatorConfigs extends AbstractInboundAuthenticatorConfig {

    private static Log log = LogFactory.getLog(SAMLAuthenticatorConfigs.class);
    //This is the key
    @Override
    public String getAuthKey() {
        return null;
    }

    @Override
    public String getConfigName() {
        return SAMLSSOConstants.SAMLFormFields.CUSTOM;
    }

    //this is the authType
    @Override
    public String getName() {
        return SAMLSSOConstants.SAMLFormFields.SAML_SSO;
    }

    @Override
    public String getFriendlyName() {
        return SAMLSSOConstants.SAMLFormFields.CUSTOM;
    }

    @Override
    public Property[] getConfigurationProperties() {
        Property issuer = new Property();
        issuer.setName(SAMLSSOConstants.SAMLFormFields.ISSUER);
        issuer.setDisplayName("Issuer");

        Property appType = new Property();
        appType.setName(SAMLSSOConstants.SAMLFormFields.WELLKNOWN_APPLICATION_TYPE);
        appType.setValue(getConfigName());
        appType.setDisplayName("UI Config Type");

        Property acsurls = new Property();
        acsurls.setName(SAMLSSOConstants.SAMLFormFields.ACS_URLS);
        acsurls.setDisplayName("Assertion Consumer URLs");
        acsurls.setDescription("The url where you should redirected after authenticated.");

        Property acsindex = new Property();
        acsindex.setName(SAMLSSOConstants.SAMLFormFields.ACS_INDEX);
        acsindex.setDisplayName("Assertion Consumer Service Index");
        try {
            acsindex.setValue(Integer.toString(IdentityUtil.getRandomInteger()));
        } catch (IdentityException e) {
            log.error("Error occurred when generating attribute consumer service index.", e);
        }

        Property defaultacs = new Property();
        defaultacs.setName(SAMLSSOConstants.SAMLFormFields.DEFAULT_ACS);
        defaultacs.setDisplayName("Default Assertion Consumer URL");

        Property nameid = new Property();
        nameid.setName(SAMLSSOConstants.SAMLFormFields.NAME_ID_FORMAT);
        nameid.setDisplayName("NameID format ");

        Property alias = new Property();
        alias.setName(SAMLSSOConstants.SAMLFormFields.ALIAS);
        alias.setDisplayName("Certificate Alias");

        Property signAlgo = new Property();
        signAlgo.setName(SAMLSSOConstants.SAMLFormFields.SIGN_ALGO);
        signAlgo.setDisplayName("Response Signing Algorithm ");
        signAlgo.setValue("http://www.w3.org/2000/09/xmldsig#dsa-sha1");

        Property digestAlgo = new Property();
        digestAlgo.setName(SAMLSSOConstants.SAMLFormFields.DIGEST_ALGO);
        digestAlgo.setDisplayName("Response Digest Algorithm ");
        digestAlgo.setValue("http://www.w3.org/2001/04/xmldsig-more#md5");

        Property enableSign = new Property();
        enableSign.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_RESPONSE_SIGNING);
        enableSign.setDisplayName("Enable Response Signing");
        enableSign.setValue("false");

        Property enableSigValidation = new Property();
        enableSigValidation.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_SIGNATURE_VALIDATION);
        enableSigValidation.setDisplayName("Enable Signature Validation in Authentication Requests and Logout " +
                "Requests");
        enableSigValidation.setValue("false");

        Property enableEncAssert = new Property();
        enableEncAssert.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_ASSERTION_ENCRYPTION);
        enableEncAssert.setDisplayName("Enable Assertion Encryption ");
        enableEncAssert.setValue("false");

        Property enableSLO = new Property();
        enableSLO.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_SINGLE_LOGOUT);
        enableSLO.setDisplayName("Enable Single Logout");
        enableSLO.setValue("false");

        Property sloUrl = new Property();
        sloUrl.setName(SAMLSSOConstants.SAMLFormFields.SLO_RESPONSE_URL);
        sloUrl.setDisplayName("SLO Response URL");

        Property sloRequestURL = new Property();
        sloRequestURL.setName(SAMLSSOConstants.SAMLFormFields.SLO_REQUEST_URL);
        sloRequestURL.setDisplayName("SLO Request URL");

        Property enableAtrProf = new Property();
        enableAtrProf.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_ATTR_PROF);
        enableAtrProf.setDisplayName("Enable Attribute Profile ");
        enableAtrProf.setValue("false");

        Property enableDefaultAtrProf = new Property();
        enableDefaultAtrProf.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_DEFAULT_ATTR_PROF);
        enableDefaultAtrProf.setDisplayName("Include Attributes in the Response Always ");
        enableDefaultAtrProf.setValue("false");

        Property enableAudienceRestriction = new Property();
        enableAudienceRestriction.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_AUDIENCE_RESTRICTION);
        enableAudienceRestriction.setDisplayName("Enable Audience Restriction ");
        enableAudienceRestriction.setValue("false");

        Property audiences = new Property();
        audiences.setName(SAMLSSOConstants.SAMLFormFields.AUDIENCE_URLS);
        audiences.setDisplayName("Audience URLs");

        Property enableRecipients = new Property();
        enableRecipients.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_RECIPIENTS);
        enableRecipients.setDisplayName("Enable Recipient Validation ");
        enableRecipients.setValue("false");

        Property receipients = new Property();
        receipients.setName(SAMLSSOConstants.SAMLFormFields.RECEIPIENT_URLS);
        receipients.setDisplayName("Recipient URLs");

        Property enableIDPSSO = new Property();
        enableIDPSSO.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_IDP_INIT_SSO);
        enableIDPSSO.setDisplayName("Enable IdP Initiated SSO ");

        Property enableIDPSLO = new Property();
        enableIDPSLO.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_IDP_INIT_SLO);
        enableIDPSLO.setDisplayName("Enable IdP Initiated SLO ");

        Property idpSLOUrls = new Property();
        idpSLOUrls.setName(SAMLSSOConstants.SAMLFormFields.IDP_SLO_URLS);
        idpSLOUrls.setDisplayName("IDP SLO Urls");

        return new Property[]{issuer, appType, acsurls, acsindex, defaultacs, nameid, alias, signAlgo, digestAlgo,
                enableSign, enableSigValidation, enableEncAssert, enableSLO, sloUrl, sloRequestURL, enableAtrProf,
                enableDefaultAtrProf, enableAudienceRestriction, audiences, enableRecipients, receipients,
                enableIDPSSO, enableIDPSLO, idpSLOUrls};
    }

    @Override
    public String getRelyingPartyKey() {
        return SAMLSSOConstants.SAMLFormFields.ISSUER;
    }
}
