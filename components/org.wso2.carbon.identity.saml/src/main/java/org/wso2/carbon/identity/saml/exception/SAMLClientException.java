/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.saml.exception;


import org.wso2.carbon.identity.gateway.api.exception.GatewayClientException;

public class SAMLClientException extends GatewayClientException {

    private String acsUrl;
    private String exceptionStatus;
    private String exceptionMessage;


    protected SAMLClientException(String errorDesciption) {
        super(errorDesciption);
    }

    protected SAMLClientException(String errorDescription,
                                  String exceptionStatus,
                                  String exceptionMessage,
                                  String acsUrl) {
        super(errorDescription);
        this.exceptionMessage = exceptionMessage;
        this.exceptionStatus = exceptionStatus;
        this.acsUrl = acsUrl;
    }

    protected SAMLClientException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }

    public static SAMLClientException error(String errorDescription) {
        return new SAMLClientException(errorDescription);
    }

    public static SAMLClientException error(String errorDescription, Throwable cause) {
        return new SAMLClientException(errorDescription, cause);
    }

    public static SAMLClientException error(String errorDescription,
                                            String exceptionStatus,
                                            String exceptionMessage,
                                            String acsUrl) {
        return new SAMLClientException(errorDescription, exceptionStatus, exceptionMessage, acsUrl);
    }

    public String getACSUrl() {
        return this.acsUrl;
    }

    public String getExceptionMessage() {
        return exceptionMessage;
    }

    public String getExceptionStatus() {
        return exceptionStatus;
    }


    public SAMLClientException(Throwable cause) {
        super(cause);
    }

    public SAMLClientException(String errorCode, String message) {
        super(errorCode, message);
    }

    public SAMLClientException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
