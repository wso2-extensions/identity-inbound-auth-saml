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
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
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

    @Override
    public void invokeBusinessLogic(MessageContext inMessageContext, MessageContext outMessageContext) throws AxisFault {
        OMElement queryOM = null;
        boolean isValidMessage;
        List<InvalidItemDTO> invalidItems = new ArrayList<InvalidItemDTO>();
        RequestAbstractType request;
        Response response;
        OMElement myOMElement;
        try {
            log.debug("Assertion Query/Request profile started with messageID:" + inMessageContext.getMessageID());
            if (inMessageContext.getEnvelope().getBody() != null) {
                //process if message body not null
                queryOM = inMessageContext.getEnvelope().getBody().getFirstElement();
                request = ((RequestAbstractType) SAMLQueryRequestUtil.unmarshall(queryOM.toString()));
                if (request != null) {
                    //validate request message
                    SAMLQueryValidator validator = SAMLValidatorFactory.getValidator(invalidItems, request);
                    isValidMessage = validator.validate(invalidItems, request);
                    if (isValidMessage && invalidItems.size() <= 0) {
                        //Process Request message
                        log.debug("Request message with id:" + request.getID() + " is completely validated");
                        SAMLQueryProcessor processor = SAMLProcessorFactory.getProcessor(request);
                        response = processor.process(request);
                        if (response != null && invalidItems.size() <= 0) {
                            // build SOAP Response message including SAML2 Response
                            String stringResponse = SAMLQueryRequestUtil.marshall((response));
                            try {
                                myOMElement = AXIOMUtil.stringToOM(stringResponse);
                                if (myOMElement != null) {
                                    SOAPEnvelope soapEnvelope = TransportUtils.createSOAPEnvelope(myOMElement);
                                    outMessageContext.setEnvelope(soapEnvelope);
                                    log.debug("SOAP response created for the request id:" + request.getID());
                                } else {
                                    //OMElement is null
                                    log.error("OMElement is null after converting String to OMElement");
                                    invalidItems.add(new InvalidItemDTO(
                                            SAMLQueryRequestConstants.ValidationType.NULL_OMELEMENT,
                                            SAMLQueryRequestConstants.ValidationMessage.NULL_OMELEMENT_ERROR));
                                }
                            } catch (XMLStreamException e) {
                                // unable to create OMElement from response XML
                                log.error("Unable to convert XML String to OMElement for " +
                                        "the request id:" + request.getID(), e);
                                invalidItems.add(new InvalidItemDTO(
                                        SAMLQueryRequestConstants.ValidationType.STRING_TO_OMELEMENT,
                                        SAMLQueryRequestConstants.ValidationMessage.STRING_TO_OMELEMENT_ERROR));
                            }
                        } else {
                            // response message is empty because no assertions or internal error
                            log.error("SAML Response is empty for the request id:" + request.getID());
                            invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.NO_ASSERTIONS,
                                    SAMLQueryRequestConstants.ValidationMessage.NO_ASSERTIONS_ERROR));
                        }
                    } else {
                        //request message contain validation errors
                        log.error("Request message with id:" + request.getID() + " contains validation errors");
                        invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_VALIDATION_ERROR,
                                SAMLQueryRequestConstants.ValidationMessage.VALIDATION_ERROR));
                    }
                } else {
                    // request message format is invalid , unable to unmarshall
                    invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_MESSAGE_TYPE,
                            SAMLQueryRequestConstants.ValidationMessage.VAL_MESSAGE_TYPE_ERROR));
                    log.error("Invalid SAML Assertion Query message type in SOAP message id:"
                            + inMessageContext.getMessageID() + ", so unable to unmarshall");
                }
            } else {
                //soap message body element is empty
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_MESSAGE_BODY,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_MESSAGE_BODY_ERROR));
                log.error("SOAP message body element is null in request id:" + inMessageContext.getMessageID());
            }
        } catch (IdentitySAML2QueryException e) {
            log.error("Unable to complete processing for the SOAP message id:" + inMessageContext.getMessageID(), e);
            invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.INTERNAL_SERVER_ERROR,
                    SAMLQueryRequestConstants.ValidationMessage.VAL_INTERNAL_SERVER_ERROR));
        }
        if (invalidItems.size() > 0) {
            //create error response message
            try {
                Response errorResponse = QueryResponseBuilder.build(invalidItems);
                if (errorResponse.getID() != null) {
                    String errorResponseText = SAMLQueryRequestUtil.marshall((errorResponse));
                    if (errorResponseText.length() > 0) {
                        OMElement errorOMElement = null;
                        try {
                            errorOMElement = AXIOMUtil.stringToOM(errorResponseText);
                            if (errorOMElement != null) {
                                SOAPEnvelope soapEnvelope = TransportUtils.createSOAPEnvelope(errorOMElement);
                                invalidItems.clear();
                                outMessageContext.setEnvelope(soapEnvelope);
                                invalidItems.clear();
                                log.debug("Error response created including error messages for the SOAP message id:"
                                        + inMessageContext.getMessageID());
                            } else {
                                log.error("Unable to generate error response, OMElement is null");
                            }
                        } catch (XMLStreamException e) {
                            log.error("Unable to generate error response, Errors in converting String to OMElement", e);
                        }
                    } else {
                        //marshall is falied
                        log.error("Unable to marshall error response message for the SOAP message id"
                                + inMessageContext.getMessageID());
                    }
                } else {
                    //error response null
                    log.error("SAML response for the error message is null");
                }
            } catch (IdentitySAML2QueryException e) {
                log.error("Unable to build SAML error response message for the message id:"
                        + inMessageContext.getMessageID(), e);
            }


        }

    }


}
