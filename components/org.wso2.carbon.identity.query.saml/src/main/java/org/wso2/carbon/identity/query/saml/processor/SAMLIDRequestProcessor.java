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
import org.opensaml.saml.saml2.core.AssertionIDRef;
import org.opensaml.saml.saml2.core.AssertionIDRequest;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.handler.SAMLAssertionFinder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAssertionFinderImpl;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to process AssertionIDRequest message
 *
 * @see AssertionIDRequest
 */
public class SAMLIDRequestProcessor implements SAMLQueryProcessor {

    private static final Log log = LogFactory.getLog(SAMLIDRequestProcessor.class);

    /**
     * This process method is for requesting existing assertion from assertion store
     *
     * @param request AssertionIDRequest from requester
     * @return Response Generated response message including assertions
     * @throws  IdentitySAML2QueryException If unable to generate SAML Response
     */
    public Response process(RequestAbstractType request) throws IdentitySAML2QueryException {
        Response response = null;
        try {
            String issuer = getIssuer(request);
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            AssertionIDRequest assertionIDRequest = (AssertionIDRequest) request;
            SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
            List<AssertionIDRef> assertionIDRefs = assertionIDRequest.getAssertionIDRefs();
            List<Assertion> assertionList = new ArrayList<Assertion>();
            for (AssertionIDRef assertionidref : assertionIDRefs) {
                List<SAMLAssertionFinder> finders = getFinders();
                String id = assertionidref.getAssertionID();
                for (SAMLAssertionFinder finder : finders) {
                    Assertion returnAssertion = finder.findByID(id);
                    if (returnAssertion != null) {
                        assertionList.add(returnAssertion);
                    }
                }
            }
            if (assertionList.size() > 0) {
                try {
                    response = QueryResponseBuilder.build(assertionList, issuerConfig, tenantDomain);
                    log.debug("Response generated with ID : " + response.getID() + " for the AssertionIDRequest id:"
                            + assertionIDRequest.getID());
                } catch (IdentitySAML2QueryException e) {
                    log.error("Unable to build response for AssertionIdRequest id:" + request.getID(), e);
                    throw new IdentitySAML2QueryException("Unable to build response for AssertionIdRequest id:"
                            + request.getID());
                }
            } else {
                //no assertions found for requested Assertion-ID
                return null;
            }
        } catch (IdentitySAML2QueryException e) {
            throw new IdentitySAML2QueryException("Unable to process AsserionIDRequest with id:" + request.getID(), e);
        }
        return response;
    }

    /**
     * This method is used to select Assertion finders
     * @return List List of different assertion finders
     * @throws IdentitySAML2QueryException If unable to read property file or NullPointer
     */
    private List<SAMLAssertionFinder> getFinders() throws IdentitySAML2QueryException {
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
                        throw new IdentitySAML2QueryException("Error while loading class for getting  assertion finders");
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
     * This method is used to get issuer from full qualified issuer value
     * @param request Assertion query request
     * @return String issuer value
     */
    private String getIssuer(RequestAbstractType request) {
        String fullQualifiedIssuer = request.getIssuer().getValue();
        return MultitenantUtils.getTenantAwareUsername(fullQualifiedIssuer);

    }

    /**
     * This method is used to get tenant domain from full qualified issuer
     * @param request Assertion query request
     * @return String tenant domain value
     */
    private String getTenantDomain(RequestAbstractType request) {
        String fullQualifiedIssuer = request.getIssuer().getValue();
        return MultitenantUtils.getTenantDomain(fullQualifiedIssuer);
    }

    /**
     * This method is used to collect service provider information
     * @param issuer name of the issuer
     * @return SAMLSSOServiceProviderDO instance of information data
     * @throws  IdentitySAML2QueryException If unable to get service provider information
     */
    protected SAMLSSOServiceProviderDO getIssuerConfig(String issuer) throws IdentitySAML2QueryException {
        return SAMLQueryRequestUtil.getServiceProviderConfig(issuer);
    }

}

