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


import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.receivers.AbstractInOutMessageReceiver;
import org.apache.axis2.transport.TransportUtils;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.processor.SAMLProcessorFactory;
import org.wso2.carbon.identity.query.saml.processor.SAMLQueryProcessor;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.identity.query.saml.validation.SAMLQueryValidator;
import org.wso2.carbon.identity.query.saml.validation.SAMLValidatorFactory;

import javax.xml.stream.XMLStreamException;
import java.util.ArrayList;
import java.util.List;

/**
 * Axis2 Message receiver for SAML2 Query Request Profile
 */
public class SAMLQueryMessageReceiver extends AbstractInOutMessageReceiver {
    OMElement queryOM = null;
    boolean isValidMessage = false;
    List<InvalidItemDTO> invalidItems = new ArrayList<InvalidItemDTO>();


    @Override
    public void invokeBusinessLogic(MessageContext inMessageContext, MessageContext outMessageContext) throws AxisFault {

        log.info(SAMLQueryRequestConstants.ServiceMessages.SERVICE_STARTED);
        if (inMessageContext.getEnvelope().getBody() != null) {
            //process if message body not null
            queryOM = inMessageContext.getEnvelope().getBody().getFirstElement();
            RequestAbstractType request = null;
            try {
                request = ((RequestAbstractType) SAMLQueryRequestUtil.unmarshall(queryOM.toString()));
            } catch (Exception ex) {
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_UNMARSHAL,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_UNMARSHAL_FAIL));
            }
            if (request != null) {
                //process only if message transformed successfully.
                SAMLQueryValidator validator = SAMLValidatorFactory.getValidator(request);
                //validate request message
                isValidMessage = validator.validate(invalidItems, request);
                if (isValidMessage) {
                    log.info(SAMLQueryRequestConstants.ServiceMessages.COMPLETE_VALIDATION);
                    //Process Request message
                    SAMLQueryProcessor processor = SAMLProcessorFactory.getProcessor(request);
                    Response response = null;
                    try {
                        Response tempResponse = processor.process(request);
                        if (tempResponse != null) {
                            response = tempResponse;
                            try {

                                String stringResponse = SAMLQueryRequestUtil.marshall((response));
                                OMElement myOMElement = null;

                                try {
                                    myOMElement = AXIOMUtil.stringToOM(stringResponse);
                                    if (myOMElement != null) {
                                        SOAPEnvelope soapEnvelope = TransportUtils.createSOAPEnvelope(myOMElement);
                                        outMessageContext.setEnvelope(soapEnvelope);

                                        log.info(SAMLQueryRequestConstants.ServiceMessages.SOAP_RESPONSE_CREATED);
                                    }
                                } catch (XMLStreamException e) {
                                    log.error(SAMLQueryRequestConstants.ServiceMessages.SOAP_RESPONSE_CREATION_FAILED);
                                }


                            } catch (IdentityException e) {
                                log.error(SAMLQueryRequestConstants.ServiceMessages.MARSHAL_ERROR);
                            }
                        } else {
                            invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.NO_ASSERTIONS,
                                    SAMLQueryRequestConstants.ValidationMessage.NO_ASSERTIONS_ERROR));
                        }


                    } catch (Exception ex) {
                        log.error(ex);
                        invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.NO_ASSERTIONS,
                                SAMLQueryRequestConstants.ValidationMessage.NO_ASSERTIONS_ERROR));
                    }
                } else {

                    log.debug("Request message contain validation issues");
                }

            } else {
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_MESSAGE_TYPE,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_MESSAGE_TYPE_ERROR));
                log.error(SAMLQueryRequestConstants.ValidationMessage.VAL_MESSAGE_TYPE_ERROR);
            }

        } else {
            invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_MESSAGE_BODY,
                    SAMLQueryRequestConstants.ValidationMessage.VAL_MESSAGE_BODY_ERROR));
            log.error(SAMLQueryRequestConstants.ValidationMessage.VAL_MESSAGE_BODY_ERROR);
        }

        if (invalidItems != null && invalidItems.size() > 0) {
            //create error response message
            try {
                Response errorResponse = QueryResponseBuilder.build(invalidItems);
                try {
                    String stringErrorResponse = SAMLQueryRequestUtil.marshall((errorResponse));
                    OMElement errorOMElement = null;

                    try {
                        errorOMElement = AXIOMUtil.stringToOM(stringErrorResponse);
                        if (errorOMElement != null) {
                            SOAPEnvelope soapEnvelope = TransportUtils.createSOAPEnvelope(errorOMElement);
                            invalidItems.clear();
                            outMessageContext.setEnvelope(soapEnvelope);
                            log.info(SAMLQueryRequestConstants.ServiceMessages.SOAP_RESPONSE_CREATED);
                        }
                    } catch (XMLStreamException e) {
                        log.error(SAMLQueryRequestConstants.ServiceMessages.SOAP_RESPONSE_CREATION_FAILED);
                    }


                } catch (IdentityException e) {
                    log.error(SAMLQueryRequestConstants.ServiceMessages.MARSHAL_ERROR);
                }


            } catch (IdentityException e) {
                log.error("Unable to build error response ", e);
            }


        }

    }


}
