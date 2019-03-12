/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml.ui;

import org.wso2.carbon.identity.sso.saml.common.SAMLSSOProviderConstants;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

import static org.apache.commons.lang.StringUtils.isNotEmpty;

public class SAMLSSOUIUtil {

    public static final boolean DEFAULT_VALUE_FOR_RESPONSE_SIGNING = true;
    public static final boolean DEFAULT_VALUE_FOR_SIGNATURE_VALIDATE_FOR_REQUESTS = true;
    public static final boolean DEFAULT_VALUE_FOR_SINGLE_LOGOUT= true;
    public static final boolean DEFAULT_VALUE_FOR_ATTRIBUTE_PROFILE= true;
    public static final boolean DEFAULT_VALUE_FOR_ECP = false;

    private SAMLSSOUIUtil() {
    }

    /**
     * Return
     *
     * @param request
     * @param parameter
     * @return
     */
    public static String getSafeInput(HttpServletRequest request, String parameter) {
        return request.getParameter(parameter);
    }

    public static SAMLSSOServiceProviderDTO[] doPaging(int pageNumber,
                                                       SAMLSSOServiceProviderDTO[] serviceProviderSet) {

        int itemsPerPageInt = SAMLSSOUIConstants.DEFAULT_ITEMS_PER_PAGE;
        SAMLSSOServiceProviderDTO[] returnedServiceProviderSet;

        int startIndex = pageNumber * itemsPerPageInt;
        int endIndex = (pageNumber + 1) * itemsPerPageInt;
        if (serviceProviderSet.length > itemsPerPageInt) {

            returnedServiceProviderSet = new SAMLSSOServiceProviderDTO[itemsPerPageInt];
        } else {
            returnedServiceProviderSet = new SAMLSSOServiceProviderDTO[serviceProviderSet.length];
        }

        for (int i = startIndex, j = 0; i < endIndex && i < serviceProviderSet.length; i++, j++) {
            returnedServiceProviderSet[j] = serviceProviderSet[i];
        }

        return returnedServiceProviderSet;
    }

    public static SAMLSSOServiceProviderDTO[] doFilter(String filter,
                                                       SAMLSSOServiceProviderDTO[] serviceProviderSet) {
        String regPattern = filter.replace("*", ".*");
        List<SAMLSSOServiceProviderDTO> list = new ArrayList<>();
        for (SAMLSSOServiceProviderDTO serviceProvider : serviceProviderSet) {
            if (serviceProvider.getIssuer().toLowerCase().matches(regPattern.toLowerCase())) {
                list.add(serviceProvider);
            }
        }
        SAMLSSOServiceProviderDTO[] filteredProviders = new SAMLSSOServiceProviderDTO[list.size()];
        for (int i = 0; i < list.size(); i++) {
            filteredProviders[i] = list.get(i);

        }

        return filteredProviders;
    }

    public static boolean isResponseSigningEnabled(boolean isSpEdit, SAMLSSOServiceProviderDTO provider) {

        if (isSpEdit) {
            if (provider != null) {
                return provider.getDoSignResponse();
            }
        } else {
            return DEFAULT_VALUE_FOR_RESPONSE_SIGNING;
        }
        return false;
    }

    public static boolean isSamlECPEnabled(boolean isSpEdit , SAMLSSOServiceProviderDTO provider ) {

        return false;
    }

    public static boolean isSignatureValidationEnabledForRequests(boolean isSpEdit, SAMLSSOServiceProviderDTO provider) {

        if (isSpEdit) {
            if (provider != null) {
                return (provider.isDoValidateSignatureInRequestsSpecified() && provider.getDoValidateSignatureInRequests());
            }
        } else {
            return DEFAULT_VALUE_FOR_SIGNATURE_VALIDATE_FOR_REQUESTS;
        }
        return false;
    }

    public static boolean isSingleLogoutEnabled(boolean isSpEdit, SAMLSSOServiceProviderDTO provider) {

        if (isSpEdit) {
            if (provider != null) {
                return provider.getDoSingleLogout();
            }
        } else {
            return DEFAULT_VALUE_FOR_SINGLE_LOGOUT;
        }
        return false;
    }

    /**
     * Check front-Channel logout enable and if not enable return false.
     * @param isSpEdit Operation on service provider, create or edit.
     * @param provider SAML2 service provider configuration.
     * @return boolean true if front channel logout enabled.
     */
    public static boolean isFrontChannelLogoutEnabled(boolean isSpEdit, SAMLSSOServiceProviderDTO provider) {

        return (isSpEdit && provider != null && provider.getDoFrontChannelLogout());
    }

    /**
     * Check front-Channel logout HTTP Redirect Binding enable and if not enable return false.
     * @param isSpEdit Operation on service provider, create or edit.
     * @param provider SAML2 service provider configuration.
     * @return boolean true if redirect binding enabled.
     */
    public static boolean isHTTPRedirectBindingEnabled(boolean isSpEdit, SAMLSSOServiceProviderDTO provider) {

        return  (isSpEdit && provider != null && SAMLSSOProviderConstants.HTTP_REDIRECT_BINDING.equals
                (provider.getFrontChannelLogoutBinding()));

    }

    /**
     * Check front-Channel logout HTTP Post Binding enable and if not enable return false.
     * @param isSpEdit Operation on service provider, create or edit.
     * @param provider SAML2 service provider configuration
     * @return boolean true if post binding enabled.
     */
    public static boolean isHTTPPostBindingEnabled(boolean isSpEdit, SAMLSSOServiceProviderDTO provider) {

        return  (isSpEdit && provider != null && SAMLSSOProviderConstants.HTTP_POST_BINDING.equals
                (provider.getFrontChannelLogoutBinding())) ;
    }

    public static boolean isAttributeProfileEnabled(boolean isSpEdit, SAMLSSOServiceProviderDTO provider) {

        if (isSpEdit) {
            if (provider != null) {
                return isNotEmpty(provider.getAttributeConsumingServiceIndex());
            }
        } else {
            return DEFAULT_VALUE_FOR_ATTRIBUTE_PROFILE;
        }
        return false;
    }
}
