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

package org.wso2.carbon.identity.query.saml.handler;

import org.opensaml.saml.saml2.core.Assertion;

import java.util.List;

/**
 * The user of the interface has facility to switch between multiple Assertion stores
 * at the run time.This interface contain multiple methods which can be used to query
 * assertions from assertion stores.
 */
public interface SAMLAssertionFinder {

    void init();

    Assertion findByID(String id);

    List<Assertion> findBySubject(String subject);


}
