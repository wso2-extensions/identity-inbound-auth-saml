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

import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.sso.samlnew.bean.message.request.SAMLIdentityRequest;

import java.io.Serializable;
import java.util.List;
import java.util.Map;


public class SAMLMessageContext<T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext {

    private boolean idpInitSSO;

    //error related properties
    private String message;
    private String destination; //needed in validation also
    private List<String> statusCodeList;
    private String inResponseToID;
    private AuthenticatedUser authzUser;

    /**
     * The unmarshelled SAML Request
     */
    private AuthnRequest authnRequest;
    private String relayState;
    /**
     * Should be set in validateAuthnRequest
     */
    private boolean isValid;



    public SAMLMessageContext(SAMLIdentityRequest request, Map<T1, T2> parameters) {
        super(request, parameters);
    }

    @Override
    public SAMLIdentityRequest getRequest() {
        return (SAMLIdentityRequest) request;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
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
        return idpInitSSO;
    }

    public void setIdpInitSSO(boolean idpInitSSO) {
        this.idpInitSSO = idpInitSSO;
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


}