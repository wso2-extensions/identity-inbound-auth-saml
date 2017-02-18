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
package org.wso2.carbon.identity.saml.validator;

import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.context.IdentityMessageContext;
import org.wso2.carbon.identity.gateway.api.response.FrameworkHandlerResponse;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.processor.handler.request.RequestHandlerException;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.saml.validators.SPInitSSOAuthnRequestValidator;

import java.io.IOException;

public class SPInitSAMLValidator extends SAMLValidator {

    private static Logger log = LoggerFactory.getLogger(SPInitSAMLValidator.class);

    @Override
    public boolean canHandle(MessageContext messageContext) {
        if (messageContext instanceof IdentityMessageContext) {
            IdentityMessageContext identityMessageContext = (IdentityMessageContext) messageContext;
            if (identityMessageContext.getIdentityRequest() instanceof SAMLSpInitRequest) {
                return true;
            }
        }

        return false;
    }

    @Override
    public FrameworkHandlerResponse validate(AuthenticationContext authenticationContext) throws RequestHandlerException {
        super.validate(authenticationContext);
        SAMLSpInitRequest identityRequest = (SAMLSpInitRequest) authenticationContext.getIdentityRequest();
        String decodedRequest;
        try {
            if (identityRequest.isRedirect()) {
                decodedRequest = SAMLSSOUtil.decode(identityRequest.getSamlRequest());
            } else {
                decodedRequest = SAMLSSOUtil.decodeForPost(identityRequest.getSamlRequest());
            }
            XMLObject request = SAMLSSOUtil.unmarshall(decodedRequest);

            if (request instanceof AuthnRequest) {
                authenticationContext.setUniqueId(((AuthnRequest) request).getIssuer().getValue());
                SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext.getParameter(SAMLSSOConstants.SAMLContext);
                validateServiceProvider(authenticationContext);
                messageContext.getSamlValidatorConfig().getAssertionConsumerUrlList();
                messageContext.setDestination(((AuthnRequest) request).getDestination());
                messageContext.setId(((AuthnRequest) request).getID());
                messageContext.setAssertionConsumerUrl(((AuthnRequest) request).getAssertionConsumerServiceURL());
                messageContext.setIsPassive(((AuthnRequest) request).isPassive());
                SPInitSSOAuthnRequestValidator reqValidator = new SPInitSSOAuthnRequestValidator(messageContext);
                if (reqValidator.validate((AuthnRequest) request)) {
                    return FrameworkHandlerResponse.CONTINUE;
                }
            }
        } catch (IdentityException e) {
            throw new RequestHandlerException("Error while validating saml request");
        } catch (IOException e) {
            throw new RequestHandlerException("Error while validating saml request");
        }
        throw new RequestHandlerException("Error while validating saml request");
    }

    public String getName() {
        return "SPInitSAMLValidator";
    }

    public int getPriority(MessageContext messageContext) {
        return 10;
    }
}
