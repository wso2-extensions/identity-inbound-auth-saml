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

package org.wso2.carbon.identity.sso.saml.configs;

import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;

public class SAMLAuthenticatorConfigs extends AbstractInboundAuthenticatorConfig {
    //This is the key
    @Override
    public String getAuthKey() {
        return "samlsso";
    }


    //this is the authType
    @Override
    public String getName() {
        return getAuthKey();
    }

    @Override
    public String getFriendlyName() {
        return "salesforce";
    }

    @Override
    public Property[] getConfigurationProperties() {
        Property issuer = new Property();
        issuer.setName(SAMLSSOConstants.SAMLFormFields.ISSUER);
        issuer.setDisplayName("Issuer");
        issuer.setValue("https://saml.salesforce.com");

        Property acsurls = new Property();
        acsurls.setName(SAMLSSOConstants.SAMLFormFields.ACS_URLS);
        acsurls.setDisplayName("Assertion Consumer URLs");
        acsurls.setDescription("The url where you should redirected after authenticated.");

        Property defaultacs = new Property();
        defaultacs.setName(SAMLSSOConstants.SAMLFormFields.DEFAULT_ACS);
        defaultacs.setDisplayName("Default Assertion Consumer URL");

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

        Property hiddenFields = new Property();
        hiddenFields.setName(SAMLSSOConstants.SAMLFormFields.HIDDEN_FIELDS);
        hiddenFields.setDisplayName("The fields that the values are set by the server.");
        hiddenFields.setValue("issuer");

        return new Property[]{issuer, acsurls, defaultacs, alias, signAlgo, digestAlgo, enableSign, enableSigValidation,
                enableEncAssert, hiddenFields};
    }
}
