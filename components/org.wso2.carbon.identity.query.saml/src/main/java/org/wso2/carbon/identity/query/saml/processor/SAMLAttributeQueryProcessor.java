/*
 *
 *  * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *  *
 *  * WSO2 Inc. licenses this file to you under the Apache License,
 *  * Version 2.0 (the "License"); you may not use this file except
 *  * in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing,
 *  * software distributed under the License is distributed on an
 *  * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  * KIND, either express or implied.  See the License for the
 *  * specific language governing permissions and limitations
 *  * under the License.
 *
 */

package org.wso2.carbon.identity.query.saml.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.*;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class is used to process attribute query requests
 *
 * @see AttributeQuery
 */
public class SAMLAttributeQueryProcessor extends SAMLSubjectQueryProcessor {

    final static Log log = LogFactory.getLog(SAMLAttributeQueryProcessor.class);

    /**
     * This method is used to process validated attribute query request.This method has capability to
     * build assertions and contain inside response message
     *
     * @param request attribute query request message
     * @return Response response message with requested assertion
     */
    @Override
    public Response process(RequestAbstractType request) {
        AttributeQuery query = (AttributeQuery) request;
        String user = getUserName(query.getSubject());
        String issuerFullName = getIssuer(request.getIssuer());
        String issuer = MultitenantUtils.getTenantAwareUsername(issuerFullName);
        String tenantdomain = MultitenantUtils.getTenantDomain(issuerFullName);
        List<Attribute> requestedattributes = query.getAttributes();
        SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
        String claimAttributes[] = getAttributesAsArray(requestedattributes);
        List<Assertion> assertions = new ArrayList<Assertion>();
        Map<String, String> attributes = getUserAttributes(user, claimAttributes, issuerConfig);
        Assertion assertion = null;
        try {
            assertion = SAMLQueryRequestUtil.buildSAMLAssertion(tenantdomain, attributes, issuerConfig);
        } catch (IdentityException e) {
            log.error(e);
        }
        assertions.add(assertion);
        Response response = null;
        try {
            response = QueryResponseBuilder.build(assertions, issuerConfig,tenantdomain);
            log.info("SAMLAttributeQueryProcessor : response generated");
        } catch (IdentityException e) {
            log.error("error occurred ", e);
        }

        return response;
    }

    /**
     * This method is used to convert required claim list into a String array
     *
     * @param claimattributes List of requested claims
     * @return String[] List of requested claims
     */
    private String[] getAttributesAsArray(List<Attribute> claimattributes) {
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
