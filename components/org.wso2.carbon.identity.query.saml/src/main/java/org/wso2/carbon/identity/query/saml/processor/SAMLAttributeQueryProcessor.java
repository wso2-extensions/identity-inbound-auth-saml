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

package org.wso2.carbon.identity.query.saml.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeQuery;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class is used to process attribute query requests
 *
 * @see AttributeQuery
 */
public class SAMLAttributeQueryProcessor extends SAMLSubjectQueryProcessor {

    private static final Log log = LogFactory.getLog(SAMLAttributeQueryProcessor.class);

    /**
     * This method is used to process validated attribute query request.This method has capability to
     * build assertions and contain inside response message
     *
     * @param request attribute query request message
     * @return Response response message with requested assertion
     * @throws  IdentitySAML2QueryException If unable to build assertion or response
     */
    @Override
    public Response process(RequestAbstractType request) throws IdentitySAML2QueryException {
        Response response = null;
        try {
            String issuer = getIssuer(request);
            String tenantDomain = getTenantDomain(request);
            AttributeQuery query = (AttributeQuery) request;
            String user = getUserName(query.getSubject());
            List<Attribute> requestedattributes = query.getAttributes();
            SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
            String claimAttributes[] = getAttributesAsArray(requestedattributes);
            List<Assertion> assertions = new ArrayList<Assertion>();
            Map<String, String> attributes = getUserAttributes(user, claimAttributes, issuerConfig);
            Assertion assertion = null;
            try {
                assertion = SAMLQueryRequestUtil.buildSAMLAssertion(tenantDomain, attributes, issuerConfig);
                assertions.add(assertion);
            } catch (IdentitySAML2QueryException e) {
                log.error("Unable to build assertion for the AttributeQuery id:" + query.getID(), e);
                throw new IdentitySAML2QueryException("Unable to build assertion for the AttributeQuery id:"
                        + query.getID(),e);
            }
            if (assertions.size() > 0) {
                try {
                    response = QueryResponseBuilder.build(assertions, issuerConfig, tenantDomain);
                    log.debug("Response generated with ID : " + response.getID() + " for the AttributeRequest Id:" +
                            query.getID());
                } catch (IdentitySAML2QueryException e) {
                    log.error("Unable to build response for the AttributeQuery with id:" + query.getID(), e);
                    throw new IdentitySAML2QueryException("Unable to build response for the AttributeQuery id:"
                            + query.getID(),e);
                }
            } else {
                return null;
            }
        } catch (IdentitySAML2QueryException e) {
            throw new IdentitySAML2QueryException("Unable to process AttributeQuery id:" + request.getID());
        }
        return response;
    }

    /**
     * This method is used to convert required claim list into a String array
     *
     * @param claimattributes List of requested claims
     * @return String[] List of requested claims
     * @throws  IdentitySAML2QueryException If friendly name is null
     */
    private String[] getAttributesAsArray(List<Attribute> claimattributes) throws IdentitySAML2QueryException {
        List<String> list = new ArrayList<String>();
        String[] claimArray = null;
        if (claimattributes.size() > 0) {
            for (Attribute attribute : claimattributes) {
                if (attribute.getFriendlyName() != null) {
                    list.add(attribute.getFriendlyName());
                }
            }
            claimArray = list.toArray(new String[list.size()]);
            return claimArray;
        }
        return claimArray;
    }
}
