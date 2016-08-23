/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.query.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.StatusMessageBuilder;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.util.OpenSAML3Util;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.List;

/**
 * This class is used to build response message for any type of request
 */
public class QueryResponseBuilder {

    private final static Log log = LogFactory.getLog(SAMLQueryRequestUtil.class);

    /**
     * @param assertions    List of assertions match with request
     * @param ssoIdPConfigs Issuer information
     * @param tenantDomain  requester's tenant domain
     * @return Response element which contain one or more assertions
     * @throws IdentityException If unable to collect issuer information
     */
    public static Response build(List<Assertion> assertions, SAMLSSOServiceProviderDO ssoIdPConfigs, String tenantDomain) throws IdentityException {
        if (log.isDebugEnabled()) {
            log.debug("Building SAML Response for the consumer '");
        }
        Response response = new ResponseBuilder().buildObject();
        response.setIssuer(OpenSAML3Util.getIssuer(tenantDomain));
        response.setID(SAMLSSOUtil.createID());
        response.setStatus(buildStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
        response.setVersion(SAMLVersion.VERSION_20);
        DateTime issueInstant = new DateTime();
        response.setIssueInstant(issueInstant);
        /**
         * adding assertions into array
         */
        for (Assertion assertion : assertions) {
            response.getAssertions().add(assertion);
        }

        //Sign on response message
        OpenSAML3Util.setSignature(response, ssoIdPConfigs.getSigningAlgorithmUri(), ssoIdPConfigs
                .getDigestAlgorithmUri(), new SignKeyDataHolder(tenantDomain));

        return response;
    }

    /**
     * This method is used to build error response when request contain validation or
     * processing errors
     *
     * @param invalidItem List of invalid items (violations)
     * @return Response element which contain error status and error message
     * @throws IdentityException If unable to collect issuer
     */
    public static Response build(List<InvalidItemDTO> invalidItem) throws IdentityException {

        Response response = new ResponseBuilder().buildObject();
        response.setIssuer(OpenSAML3Util.getIssuer(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME));
        response.setID(SAMLSSOUtil.createID());
        String statusCode = "";
        String statusMessage = "";

        //selecting Status Code
        if (invalidItem.size() > 0) {
            statusMessage = invalidItem.get(0).getMessage();
            statusCode = invalidItem.get(0).getValidationType();
            statusCode = filterStatusCode(statusCode);
        }
        response.setStatus(buildStatus(statusCode, statusMessage));
        response.setVersion(SAMLVersion.VERSION_20);
        DateTime issueInstant = new DateTime();
        response.setIssueInstant(issueInstant);

        return response;
    }

    /**
     * This method is used to get status of message
     *
     * @param status  response message Status
     * @param statMsg status message of the response
     * @return Status object of Status element
     */
    public static Status buildStatus(String status, String statMsg) {

        Status stat = new StatusBuilder().buildObject();

        // Set the status code
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue(status);
        stat.setStatusCode(statCode);

        // Set the status Message
        if (statMsg != null) {
            StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
            statMesssage.setMessage(statMsg);
            stat.setStatusMessage(statMesssage);
        }

        return stat;
    }

    /**
     * This method is used to select error message according to error type
     *
     * @param validationType error type
     * @return String error message
     * @see SAMLQueryRequestConstants
     */
    public static String filterStatusCode(String validationType) {
        String statusCode;
        if (validationType.equalsIgnoreCase(SAMLQueryRequestConstants.ValidationType.VAL_VERSION)) {
            statusCode = SAMLSSOConstants.StatusCodes.VERSION_MISMATCH;
        } else if (validationType.equalsIgnoreCase(SAMLQueryRequestConstants.ValidationType.VAL_ISSUER)) {
            statusCode = SAMLSSOConstants.StatusCodes.UNKNOWN_PRINCIPAL;
        } else if (validationType.equalsIgnoreCase(SAMLQueryRequestConstants.ValidationType.VAL_SIGNATURE)) {
            statusCode = SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR;
        } else if (validationType.equalsIgnoreCase(SAMLQueryRequestConstants.ValidationType.VAL_MESSAGE_TYPE)) {
            statusCode = SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR;
        } else if (validationType.equalsIgnoreCase(SAMLQueryRequestConstants.ValidationType.VAL_MESSAGE_BODY)) {
            statusCode = SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR;
        } else if (validationType.equalsIgnoreCase(SAMLQueryRequestConstants.ValidationType.NO_ASSERTIONS)) {
            statusCode = StatusCode.NO_AUTHN_CONTEXT;
        } else {
            statusCode = SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR;
        }
        return statusCode;
    }


}
