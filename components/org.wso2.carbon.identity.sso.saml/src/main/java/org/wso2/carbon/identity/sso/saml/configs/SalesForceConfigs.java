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

package org.wso2.carbon.identity.sso.saml.configs;

import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;

public class SalesForceConfigs extends SAMLAuthenticatorConfigs {
    //This is the key
    @Override
    public String getAuthKey() {
        return null;
    }


    //this is the authType
    @Override
    public String getName() {
        return super.getName();
    }

    @Override
    public String getConfigName(){
        return "salesforce";
    }

    @Override
    public String getFriendlyName() {
        return "salesforce";
    }

    @Override
    public Property[] getConfigurationProperties() {
        Property[] samlProps = super.getConfigurationProperties();
        Property hiddenFields = new Property();
        hiddenFields.setName(SAMLSSOConstants.SAMLFormFields.HIDDEN_FIELDS);
        hiddenFields.setDisplayName("Hidden Fields");
        hiddenFields.setValue(getHiddenFields(new String[]{SAMLSSOConstants.SAMLFormFields.ISSUER, SAMLSSOConstants
                .SAMLFormFields.ENABLE_SINGLE_LOGOUT, SAMLSSOConstants.SAMLFormFields.SLO_RESPONSE_URL,
                SAMLSSOConstants.SAMLFormFields.SLO_REQUEST_URL, SAMLSSOConstants.SAMLFormFields.ENABLE_ATTR_PROF,
                SAMLSSOConstants.SAMLFormFields.ENABLE_DEFAULT_ATTR_PROF, SAMLSSOConstants.SAMLFormFields
                .ENABLE_AUDIENCE_RESTRICTION, SAMLSSOConstants.SAMLFormFields.AUDIENCE_URLS, SAMLSSOConstants
                .SAMLFormFields.ENABLE_RECIPIENTS, SAMLSSOConstants.SAMLFormFields.RECEIPIENT_URLS, SAMLSSOConstants
                .SAMLFormFields.ENABLE_IDP_INIT_SSO, SAMLSSOConstants.SAMLFormFields.ENABLE_IDP_INIT_SLO,
                SAMLSSOConstants.SAMLFormFields.IDP_SLO_URLS}));

        Property[] properties = new Property[samlProps.length + 1];
        System.arraycopy(samlProps, 0, properties, 0, properties.length - 1);
        properties[properties.length - 1] = hiddenFields;
        return properties;
    }

    @Override
    public String getRelyingPartyKey() {
        return SAMLSSOConstants.SAMLFormFields.ISSUER;
    }

    private String getHiddenFields(String[] hiddenFields) {
        StringBuilder hiddenFieldsStr = new StringBuilder();
        for (int cntr = 0; cntr < hiddenFields.length; cntr++) {
            if (cntr != hiddenFields.length - 1) {
                hiddenFieldsStr.append(hiddenFields[cntr] + SAMLSSOConstants.SAMLFormFields.ACS_SEPERATE_CHAR);
            } else {
                hiddenFieldsStr.append(hiddenFields[cntr]);
            }
        }
        return hiddenFieldsStr.toString();
    }
}
