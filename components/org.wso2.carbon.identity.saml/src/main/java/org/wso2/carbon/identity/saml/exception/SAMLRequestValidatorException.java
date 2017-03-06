/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.saml.exception;

import org.wso2.carbon.identity.gateway.exception.RequestValidatorException;
import org.wso2.carbon.identity.saml.util.SAML2URI;


public class SAMLRequestValidatorException extends RequestValidatorException {

    private SAMLErrorInfo samlErrorInfo = null;

    public SAMLRequestValidatorException(SAMLErrorInfo samlErrorInfo) {
        super(samlErrorInfo.getMessage());
    }

    public SAMLRequestValidatorException(String errorCode, SAMLErrorInfo samlErrorInfo) {
        super(errorCode, samlErrorInfo.getMessage());
    }

    public SAMLRequestValidatorException(String message) {
        super(message);
    }

    public SAMLRequestValidatorException(Throwable cause) {
        super(cause);
    }

    public SAMLRequestValidatorException(String errorCode, String message) {
        super(errorCode, message);
    }

    public SAMLRequestValidatorException(String message, Throwable cause) {
        super(message, cause);
    }

    public SAMLRequestValidatorException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }

    public SAMLErrorInfo getSamlErrorInfo() {
        return samlErrorInfo;
    }

    public void setSamlErrorInfo(SAMLErrorInfo samlErrorInfo) {
        this.samlErrorInfo = samlErrorInfo;
    }

    public static class SAMLErrorInfo {
        private SAML2URI saml2URI;
        private String message;
        private String destination;

        public SAMLErrorInfo(SAML2URI saml2URI, String message, String destination) {
            this.saml2URI = saml2URI;
            this.message = message;
            this.destination = destination;
        }

        public String getDestination() {
            return destination;
        }

        public void setDestination(String destination) {
            this.destination = destination;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public SAML2URI getSaml2URI() {
            return saml2URI;
        }

        public void setSaml2URI(SAML2URI saml2URI) {
            this.saml2URI = saml2URI;
        }
    }
}
