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
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectQuery;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.handler.SAMLAssertionFinder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAssertionFinderImpl;
import org.wso2.carbon.identity.query.saml.handler.SAMLAttributeFinder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAttributeFinderImpl;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This calss is used to process common elements of
 * AttributeQuery, AuthnQuery,
 * AuthorizationDecisionQuery, SubjectQuery messages.This class is the parent of given class list.
 */
public class SAMLSubjectQueryProcessor implements SAMLQueryProcessor {
    /**
     * Standard logging
     */
    final static Log log = LogFactory.getLog(SAMLSubjectQueryProcessor.class);

    /**
     * This method used to generate response object according to subject
     * @param request assertion request message
     * @return Response container of one or more assertions
     * @throws  IdentitySAML2QueryException  If unable to load issuerconfig, user attributes, and build assertions.
     */
    public Response process(RequestAbstractType request) throws IdentitySAML2QueryException {
            Response response = null;
            String issuer = getIssuer(request);
            String tenantDomain = getTenantDomain(request);
            SubjectQuery query = (SubjectQuery) request;
            String user = getUserName(query.getSubject());
            SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
            Map<String, String> attributes = getUserAttributes(user, null, issuerConfig);
            Assertion assertion = null;
            List<Assertion> assertions = null;
            try {
                assertion = SAMLQueryRequestUtil.buildSAMLAssertion(tenantDomain, attributes, issuerConfig);
                assertions.add(assertion);
            }  catch (NullPointerException e) {
                log.error("No assertions for the subject:" + user + " and request id:" + query.getID(), e);
                throw new IdentitySAML2QueryException("No assertions for the subject:" + user + " and request id:" +
                        query.getID());
            }
            if (assertions.size() > 0) {
                try {
                    response = QueryResponseBuilder.build(assertions, issuerConfig, user);
                    log.debug("Response generated with ID : " + response.getID() + " For the request id:" +
                            query.getID());
                } catch (IdentitySAML2QueryException e) {
                    log.error("Unable to build response for the request id:" + query.getID(), e);
                    throw new IdentitySAML2QueryException("Unable to build response for the request id:" +
                            query.getID());
                }
            } else {
                return null;
            }
        return response;
    }

    /**
     * This method used to load issuer config
     * @param issuer issuer name
     * @return SAMLSSOServiceProviderDO issuer config object
     * @throws IdentitySAML2QueryException If unable to load service provider configuration
     */
    protected SAMLSSOServiceProviderDO getIssuerConfig(String issuer) throws IdentitySAML2QueryException {
        try {
            return SAMLQueryRequestUtil.getServiceProviderConfig(issuer);
        } catch (IdentityException e) {
            log.error("Unable to load service provider configurations for the service provider:" + issuer, e);
            throw new IdentitySAML2QueryException("Unable to load service provider configurations for the issuer:"
                    + issuer);
        }
    }

    /**
     * method to load user attributes in a map with filtering(AttributeQuery)
     *
     * @param user         user name with tenant domain
     * @param attributes   list of requested attributes
     * @param issuerConfig issuer config information
     * @return Map List of user attributes
     * @throws  IdentitySAML2QueryException If unable to load Attributes
     */
    protected Map<String, String> getUserAttributes(String user, String[] attributes,
                                                    Object issuerConfig) throws IdentitySAML2QueryException {
        List<SAMLAttributeFinder> finders = getAttributeFinders();
        for (SAMLAttributeFinder finder : finders) {
            Map<String, String> attributeMap = finder.getAttributes(user, attributes);
            if (attributeMap != null && attributeMap.size() > 0) {
                return attributeMap;
            }
        }
        return null;
    }

    /**
     * method used to get subject value
     * @param subject subject element of request message
     * @return String subject value
     */
    protected String getUserName(Subject subject) {

        return subject.getNameID().getValue();
    }

    /**
     * method used to select attribute finder source
     * @return List list of attribute finders
     * @throws  IdentitySAML2QueryException If unable to read property file
     */
    private List<SAMLAttributeFinder> getAttributeFinders() throws IdentitySAML2QueryException {

        List<SAMLAttributeFinder> finders = new ArrayList<SAMLAttributeFinder>();

        String finderClassesString = IdentityUtil.getProperty(
                SAMLQueryRequestConstants.GenericConstants.ATTRIBUTE_HANDLER);
        if (finderClassesString != null && finderClassesString.trim().length() > 0) {
            String[] finderClasses = finderClassesString.trim().split(
                    SAMLQueryRequestConstants.GenericConstants.HANDLER_PROPERY_DELIMETER);
            for (String finderClass : finderClasses) {
                synchronized (Runtime.getRuntime().getClass()) {
                    try {
                        SAMLAttributeFinder finder =
                                (SAMLAttributeFinder) Class.forName(finderClass.trim()).newInstance();
                        finder.init();
                        finders.add(finder);
                    } catch (ClassNotFoundException e) {
                        log.error("Unable to find class for getting attribute finders", e);
                        throw new IdentitySAML2QueryException("Unable to find class for getting  attribute finders");
                    } catch (InstantiationException e) {
                        log.error("Unable to initiate class for getting attribute finders", e);
                        throw new IdentitySAML2QueryException("Unable to initiate class for getting attribute finders");
                    } catch (IllegalAccessException e) {
                        log.error("Unable to access class for getting attribute finders", e);
                        throw new IdentitySAML2QueryException("Unable to access class for getting attribute finders");
                    }
                }
            }
        } else {
            finders.add(new SAMLAttributeFinderImpl());
        }
        return finders;
    }

    /**
     * This method is used to select Assertion finders
     * @return List List of different assertion finders
     * @throws  IdentitySAML2QueryException If unable to read property file
     */
    protected List<SAMLAssertionFinder> getFinders() throws IdentitySAML2QueryException {
        List<SAMLAssertionFinder> finders = new ArrayList<SAMLAssertionFinder>();
        String finderClassesString = IdentityUtil.getProperty(
                SAMLQueryRequestConstants.GenericConstants.ASSERTION_HANDLER);
        if (finderClassesString != null && finderClassesString.trim().length() > 0) {
            String[] finderClasses = finderClassesString.trim().split(
                    SAMLQueryRequestConstants.GenericConstants.HANDLER_PROPERY_DELIMETER);
            for (String finderClass : finderClasses) {
                synchronized (Runtime.getRuntime().getClass()) {
                    try {
                        SAMLAssertionFinder finder =
                                (SAMLAssertionFinder) Class.forName(finderClass.trim()).newInstance();
                        finder.init();
                        finders.add(finder);
                    } catch (ClassNotFoundException e) {
                        log.error("Error while loading class for getting assertion finders", e);
                        throw new IdentitySAML2QueryException("Error while loading class for getting assertion finders");
                    } catch (InstantiationException e) {
                        log.error("Unable to initiate class for getting assertion finders", e);
                        throw new IdentitySAML2QueryException("Unable to initiate class for getting assertion finders");
                    } catch (IllegalAccessException e) {
                        log.error("Unable to access class for getting assertion finders", e);
                        throw new IdentitySAML2QueryException("Unable to access class for getting assertion finders");
                    }
                }
            }
        } else {
            finders.add(new SAMLAssertionFinderImpl());
        }
        return finders;
    }

    /**
     * This method is used to get issuer name from full qualified issuer value
     * @param request Assertion request message
     * @return String issuer name
     */
    protected String getIssuer(RequestAbstractType request) {
        String fullQualifiedIssuer = request.getIssuer().getValue();
        return MultitenantUtils.getTenantAwareUsername(fullQualifiedIssuer);
    }

    /**
     * This method is used to get tenant domain from full qualified issuer value
     * @param request Assertion request message
     * @return String tenant domain value
     */
    protected String getTenantDomain(RequestAbstractType request) {
        String fullQualifiedIssuer = request.getIssuer().getValue();
        return MultitenantUtils.getTenantDomain(fullQualifiedIssuer);
    }

    /**
     * This method is used to get subject value along with tenant domain
     * @param request Assertion request message
     * @param tenantDomain Tenant domain of the subject
     * @return String full qualified subject value
     */
    protected String getFullQualifiedSubject(SubjectQuery request, String tenantDomain) {
        return request.getSubject().getNameID().getValue() + "@" + tenantDomain;
    }

}
