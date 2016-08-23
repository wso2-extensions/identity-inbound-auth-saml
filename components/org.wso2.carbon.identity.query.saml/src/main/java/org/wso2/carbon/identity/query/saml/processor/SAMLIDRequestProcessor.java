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
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAssertionFinder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAssertionFinderImpl;
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

    private final static Log log = LogFactory.getLog(SAMLIDRequestProcessor.class);

    /**
     * This process method is for requesting existing assertion from assertion store
     *
     * @param request AssertionIDRequest from requester
     * @return Response Generated response message including assertions
     */
    public Response process(RequestAbstractType request) {
        Response response = null;
        try {
            AssertionIDRequest assertion = (AssertionIDRequest) request;
            String issuerFullName = getIssuer(request.getIssuer());
            String issuer = MultitenantUtils.getTenantAwareUsername(issuerFullName);
            String tenantdomain = MultitenantUtils.getTenantDomain(issuerFullName);
            SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
            List<AssertionIDRef> assertionIDRefs = assertion.getAssertionIDRefs();
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
                    response = QueryResponseBuilder.build(assertionList, issuerConfig, tenantdomain);
                    log.debug("Response generated with ID : " + response.getID());
                } catch (IdentityException e) {
                    log.error("Unable to build response for SAMLIDRequest ", e);
                }
            }
        } catch (Exception ex) {
            log.error("Unable to process AssertionIDRequest ", ex);
        }
        return response;
    }

    /**
     * This method is used to select Assertion finders
     *
     * @return List List of different assertion finders
     */
    private List<SAMLAssertionFinder> getFinders() {
        List<SAMLAssertionFinder> finders = new ArrayList<SAMLAssertionFinder>();
        SAMLAssertionFinder finder = new SAMLAssertionFinderImpl();
        finder.init();
        finders.add(finder);
        return finders;
    }


    /**
     * This method is used to get issuer value
     *
     * @param issuer Issuer element of request message
     * @return String full qualified issuer name Ex: xxxx@carbon.super
     */
    protected String getIssuer(Issuer issuer) {

        return issuer.getValue();
    }

    /**
     * This method is used to collect service provider information
     *
     * @param issuer name of the issuer
     * @return SAMLSSOServiceProviderDO instance of information data
     */
    protected SAMLSSOServiceProviderDO getIssuerConfig(String issuer) {

        try {
            return SAMLQueryRequestUtil.getServiceProviderConfig(issuer);
        } catch (IdentityException e) {
            log.error("Unable to get service provider information ", e);
        }
        return null;
    }

}

