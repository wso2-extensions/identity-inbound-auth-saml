/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.samlnew.bean.context;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.samlnew.bean.message.request.SAMLIdentityRequest;

import java.io.Serializable;
import java.util.List;
import java.util.Map;


public class SAMLMessageContext<T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext {


    //error related properties
    private String response;
    private List<String> statusCodeList;
    private String inResponseToID;
    private AuthenticatedUser authzUser;

    /**
     * The unmarshelled SAML Request
     */
    private AuthnRequest authnRequest;

    /**
     * Should be set in validateAuthnRequest
     */
    private boolean isValid;
    private String queryString;
    private String destination; //needed in validation also
    private String relayState;
    private String requestMessageString;
    private String issuer;
    private String id;
    private String subject;
    private String rpSessionId;
    private String assertionConsumerURL;
    private String tenantDomain;
    private int attributeConsumingServiceIndex;
    private boolean isForceAuthn;
    private boolean isPassive;
    private boolean isIdpInitSSO;
    private boolean isStratosDeployment;
    private SAMLSSOServiceProviderDO samlssoServiceProviderDO;


    public SAMLMessageContext(SAMLIdentityRequest request, Map<T1, T2> parameters) {
        super(request, parameters);
    }

    @Override
    public SAMLIdentityRequest getRequest() {
        return (SAMLIdentityRequest) request;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public List<String> getStatusCodeList() {
        return statusCodeList;
    }

    public void setStatusCodeList(List<String> statusCodeList) {
        this.statusCodeList = statusCodeList;
    }

    public String getInResponseToID() {
        return inResponseToID;
    }

    public void setInResponseToID(String inResponseToID) {
        this.inResponseToID = inResponseToID;
    }

    public boolean isIdpInitSSO() {
        return isIdpInitSSO;
    }

    public void setIdpInitSSO(boolean idpInitSSO) {
        this.isIdpInitSSO = idpInitSSO;
    }

    public AuthenticatedUser getAuthzUser() {
        return authzUser;
    }

    public void setAuthzUser(AuthenticatedUser authzUser) {
        this.authzUser = authzUser;
    }

    public AuthnRequest getAuthnRequest() {
        return authnRequest;
    }

    public void setAuthnRequest(AuthnRequest authnRequest) {
        this.authnRequest = authnRequest;
    }

    public String getRelayState() {
        return relayState;
    }

    public void setRelayState(String relayState) {
        this.relayState = relayState;
    }

    public boolean isValid() {
        return isValid;
    }

    public void setValid(boolean isValid) {
        this.isValid = isValid;
    }

    public String getQueryString() {
        return queryString;
    }

    public void setQueryString(String queryString) {
        this.queryString = queryString;
    }

    public String getIssuer() {
        if (issuer.contains("@")) {
            String[] splitIssuer = issuer.split("@");
            return splitIssuer[0];
        }
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getIssuerWithDomain() {
        return this.issuer;
    }

    public int getAttributeConsumingServiceIndex() {
        return attributeConsumingServiceIndex;
    }

    public void setAttributeConsumingServiceIndex(int attributeConsumingServiceIndex) {
        this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
    }

    public String getRpSessionId() {
        return rpSessionId;
    }

    public void setRpSessionId(String rpSessionId) {
        this.rpSessionId = rpSessionId;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAssertionConsumerURL() {
        return assertionConsumerURL;
    }

    public void setAssertionConsumerURL(String assertionConsumerURL) {
        this.assertionConsumerURL = assertionConsumerURL;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public String getRequestMessageString() {
        return requestMessageString;
    }

    public void setRequestMessageString(String requestMessageString) {
        this.requestMessageString = requestMessageString;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public boolean isForceAuthn() {
        return isForceAuthn;
    }

    public void setForceAuthn(boolean isForceAuthn) {
        this.isForceAuthn = isForceAuthn;
    }

    public boolean isPassive() {
        return isPassive;
    }

    public void setPassive(boolean isPassive) {
        this.isPassive = isPassive;
    }

    public AuthenticationResult getAuthenticationResult() {
        if (this.getParameter(SAMLSSOConstants.AUTHENTICATION_RESULT) != null) {
            return (AuthenticationResult) this.getParameter(SAMLSSOConstants.AUTHENTICATION_RESULT);
        }
        return new AuthenticationResult();
    }

    public SAMLSSOServiceProviderDO getSamlssoServiceProviderDO() {
        return samlssoServiceProviderDO;
    }

    public void setSamlssoServiceProviderDO(SAMLSSOServiceProviderDO samlssoServiceProviderDO) {
        this.samlssoServiceProviderDO = samlssoServiceProviderDO;
    }

    public boolean isStratosDeployment() {
        return isStratosDeployment;
    }

    public void setStratosDeployment(boolean isStratosDeployment) {
        this.isStratosDeployment = isStratosDeployment;
    }
}