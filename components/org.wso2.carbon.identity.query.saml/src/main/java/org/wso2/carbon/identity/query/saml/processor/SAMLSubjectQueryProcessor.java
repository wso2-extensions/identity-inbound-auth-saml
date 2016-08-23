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
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectQuery;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAttributeFinder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAttributeFinderImpl;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This calss is used to process common elements of
 * AttributeQuery,AuthnQuery,
 * AuthorizationDecisionQuery,SubjectQuery messages.This class is the parent of
 * given class list.
 */
public class SAMLSubjectQueryProcessor implements SAMLQueryProcessor {

    final static Log log = LogFactory.getLog(SAMLSubjectQueryProcessor.class);

    /**
     * This method used to generate response object according to subject
     *
     * @param request assertion request message
     * @return Response container of one or more assertions
     */
    public Response process(RequestAbstractType request) {
        Response response = null;
        try {
            SubjectQuery query = (SubjectQuery) request;
            String user = getUserName(query.getSubject());
            String issuerFullName = getIssuer(request.getIssuer());
            String issuer = MultitenantUtils.getTenantAwareUsername(issuerFullName);
            String tenantdomain = MultitenantUtils.getTenantDomain(issuerFullName);
            SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
            Map<String, String> attributes = getUserAttributes(user, null, issuerConfig);
            Assertion assertion = null;
            List<Assertion> assertions = null;
            try {
                assertion = SAMLQueryRequestUtil.buildSAMLAssertion(tenantdomain, attributes, issuerConfig);
                assertions.add(assertion);
            } catch (IdentityException e) {
                log.error("Unable to build assertion ", e);
            } catch (NullPointerException e) {
                log.error("No assertions to add into list", e);
            }


            try {
                response = QueryResponseBuilder.build(assertions, issuerConfig, user);
                log.debug("Response generated with ID : " + response.getID());
            } catch (IdentityException e) {
                log.error("Unable to build response ", e);
            }
        } catch (Exception ex) {
            log.error("Unable to process SubjectQuery", ex);
        }

        return response;
    }

    /**
     * This method used to load issuer config
     *
     * @param issuer issuer name
     * @return SAMLSSOServiceProviderDO issuer config object
     */
    protected SAMLSSOServiceProviderDO getIssuerConfig(String issuer) {

        try {
            return SAMLQueryRequestUtil.getServiceProviderConfig(issuer);
        } catch (IdentityException e) {
            log.error("Unable to load service provider configurations", e);
        }
        return new SAMLSSOServiceProviderDO();
    }

    /**
     * method to load user attributes in a map with filtering(AttributeQuery)
     *
     * @param user         user name with tenant domain
     * @param attributes   list of requested attributes
     * @param issuerConfig issuer config information
     * @return Map List of user attributes
     */
    protected Map<String, String> getUserAttributes(String user, String[] attributes,
                                                    Object issuerConfig) {

        List<SAMLAttributeFinder> finders = getAttributeFinders();

        for (SAMLAttributeFinder finder : finders) {
            Map<String, String> attributeMap = finder.getAttributes(user, attributes);
            if (attributeMap != null && attributeMap.size() > 0) {
                //filter attributes based on attribute query here
                return attributeMap;
            }
        }

        return new HashMap<String, String>();
    }

    /**
     * get issuer value
     *
     * @param issuer issuer element
     * @return String issuer name
     */
    protected String getIssuer(Issuer issuer) {

        return issuer.getValue();
    }

    /**
     * method used to get subject value
     *
     * @param subject subject element of request message
     * @return String subject value
     */
    protected String getUserName(Subject subject) {

        return subject.getNameID().getValue();
    }

    /**
     * method used to select attribute finder source
     *
     * @return List list of attribute finders
     */
    private List<SAMLAttributeFinder> getAttributeFinders() {

        List<SAMLAttributeFinder> finders = new ArrayList<SAMLAttributeFinder>();
        finders.add(new SAMLAttributeFinderImpl());
        return finders;
    }

}
