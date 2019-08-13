/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
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

package org.wso2.carbon.identity.sso.saml.extension.eidas.model;

import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.wso2.carbon.identity.sso.saml.extension.eidas.util.EidasConstants;

import java.util.List;
import javax.xml.namespace.QName;

/**
 * SAML Metadata RequestedAttributes.
 */
public interface RequestedAttributes extends SAMLObject {

    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "RequestedAttributes";

    public static final QName DEFAULT_ELEMENT_NAME = new QName(EidasConstants.EIDAS_NS, DEFAULT_ELEMENT_LOCAL_NAME,
            EidasConstants.EIDAS_PREFIX);

    public static final String TYPE_LOCAL_NAME = "RequestedAttributesType";

    /**
     * Returns a reference to the list of the requested attributes.
     *
     * @return an attribute list
     */
    public List<RequestedAttribute> getRequestedAttributes();

}
