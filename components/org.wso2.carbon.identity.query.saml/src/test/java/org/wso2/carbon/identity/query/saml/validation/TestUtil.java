/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.query.saml.validation;

import org.opensaml.core.xml.util.XMLObjectChildrenList;

import org.opensaml.saml.saml2.core.Action;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.impl.ActionImpl;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefImpl;
import org.opensaml.saml.saml2.core.impl.AuthnQueryImpl;
import org.opensaml.saml.saml2.core.impl.AuthzDecisionQueryImpl;
import org.opensaml.saml.saml2.core.impl.IssuerImpl;
import org.opensaml.saml.saml2.core.impl.NameIDImpl;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextImpl;
import org.opensaml.saml.saml2.core.impl.SubjectImpl;
import org.opensaml.saml.saml2.core.impl.SubjectQueryImpl;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;

import java.nio.file.Paths;
import java.util.List;

/**
 * Utilclasses for testcases.
 */
public class TestUtil {


    public static void initPrivilegedCarbonContext(String tenantDomain, int tenantID, String userName) {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
    }

    public static void stopPrivilegedCarbonContext() {
        PrivilegedCarbonContext.endTenantFlow();
        System.clearProperty(CarbonBaseConstants.CARBON_HOME);
    }

}

class DummySubjectQueryImpl extends SubjectQueryImpl {

    protected DummySubjectQueryImpl() {
        super("testNSU", "testELN", "testNSP");
    }

    Subject subject;

    @Override
    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    @Override
    public Subject getSubject() {
        return subject;
    }
}

class DummySubject extends SubjectImpl {

    protected DummySubject() {
        super("testNSU", "testELN", "testNSP");
    }

    NameID nameID;

    @Override
    public void setNameID(NameID newNameID) {
        nameID = newNameID;
    }

    @Override
    public NameID getNameID() {
        return nameID;
    }
}

class DummyNameID extends NameIDImpl {

    protected DummyNameID() {
        super("testNSU", "testELN", "testNSP");
    }

    String format;
    String value;

    @Override
    public void setFormat(String newFormat) {
        format = newFormat;
        value = newFormat;
    }

    @Override
    public String getFormat() {
        return format;
    }

    @Override
    public String getValue() {
        return value;
    }
}

class DummyIssuer extends IssuerImpl {

    protected DummyIssuer() {
        super("testNSU", "testELN", "testNSP");
    }

}

class dummyAuthnQueryImpl extends AuthnQueryImpl {

    protected dummyAuthnQueryImpl() {
        super("testNSU", "testELN", "testNSP");
    }

    NameID nameID;

    public void setNameID(NameID newNameID) {
        nameID = newNameID;
    }

    public NameID getNameID() {
        return nameID;
    }
}

class DummyReqAuthnContext extends RequestedAuthnContextImpl {

    private final XMLObjectChildrenList<AuthnContextClassRef> authnContextClassRefs = new XMLObjectChildrenList(this);

    protected DummyReqAuthnContext() {
        super("testNSU", "testELN", "testNSP");
    }

    public void setAuthnContextClassRefs() {
        DummyAuthContext sample = new DummyAuthContext();
        this.authnContextClassRefs.add(sample);
    }

    @Override
    public XMLObjectChildrenList<AuthnContextClassRef> getAuthnContextClassRefs() {
        return authnContextClassRefs;
    }
}

class DummyAuthContext extends AuthnContextClassRefImpl {

    protected DummyAuthContext() {
        super("testNSU", "testELN", "testNSP");
    }
}

class DummyAuthDecisionQuery extends AuthzDecisionQueryImpl {
    private final XMLObjectChildrenList<Action> actions = new XMLObjectChildrenList(this);
    String resource;

    protected DummyAuthDecisionQuery() {
        super("testNSU", "testELN", "testNSP");
    }

    NameID nameID;

    public void setNameID(NameID newNameID) {
        nameID = newNameID;
    }

    public NameID getNameID() {
        return nameID;
    }

    public void setactions() {
        DummyActions dummyaction = new DummyActions();
        actions.add(dummyaction);
    }

    public List<Action> getActions() {
        return this.actions;
    }

    @Override
    public void setResource(String resource) {
        this.resource = resource;
    }

    @Override
    public String getResource() {
        return resource;
    }
}

class DummyActions extends ActionImpl {

    protected DummyActions() {
        super("testNSU", "testELN", "testNSP");
    }
}

