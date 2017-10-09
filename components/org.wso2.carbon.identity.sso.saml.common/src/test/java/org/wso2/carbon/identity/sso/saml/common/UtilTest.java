package org.wso2.carbon.identity.sso.saml.common;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;

import java.lang.reflect.Array;
import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;


public class UtilTest {

    private static int singleLogoutRetryCount = 5;
    private static long singleLogoutRetryInterval = 60000;


    @Test
    public void testGetSingleLogoutRetryCount() throws Exception {
        int singleLogoutRetryC= Util.getSingleLogoutRetryCount();
        Assert.assertEquals(singleLogoutRetryC,singleLogoutRetryCount);
    }

    @Test
    public void testSetSingleLogoutRetryCount() throws Exception {
        Util.setSingleLogoutRetryCount(6);
        Assert.assertEquals(Util.getSingleLogoutRetryCount(),6);
        Util.setSingleLogoutRetryCount(singleLogoutRetryCount);
    }

    @Test
    public void testGetSingleLogoutRetryInterval() throws Exception {
        long singleLogoutRetryInt =Util.getSingleLogoutRetryInterval();
        Assert.assertEquals(singleLogoutRetryInt,singleLogoutRetryInterval);
    }

    @Test
    public void testSetSingleLogoutRetryInterval() throws Exception {
        Util.setSingleLogoutRetryInterval(70000);
        Assert.assertEquals(Util.getSingleLogoutRetryInterval(),70000);
        Util.setSingleLogoutRetryInterval(singleLogoutRetryInterval);
    }

    @DataProvider(name = "provideHttpStatusCode")
    public Object[][] createData1() {
        return new Object[][] {
                { 200, true },
                { 300, false},
                { 100, false},
                { 0, false},
        };
    }

    @Test(dataProvider = "provideHttpStatusCode")
    public void testIsHttpSuccessStatusCode(int status,boolean value) throws Exception {
        Assert.assertEquals(Util.isHttpSuccessStatusCode(status),value);
    }
    @DataProvider(name = "provideServiceProvider")
    public Object[][] createServiceProvider() {
        SAMLSSOServiceProviderDTO SP1 = new SAMLSSOServiceProviderDTO();
        SP1.setIssuer("test1");
        SAMLSSOServiceProviderDTO SP2 = new SAMLSSOServiceProviderDTO();
        SP2.setIssuer("test2=");
        SAMLSSOServiceProviderDTO SP3 = new SAMLSSOServiceProviderDTO();
        SP3.setIssuer("test3");
        SAMLSSOServiceProviderDTO SP4 = new SAMLSSOServiceProviderDTO();
        SP4.setIssuer("test4");
        SAMLSSOServiceProviderDTO SP5 = new SAMLSSOServiceProviderDTO();
        SP5.setIssuer("test5=");
        SAMLSSOServiceProviderDTO SP6 = new SAMLSSOServiceProviderDTO();
        SP6.setIssuer("test6=");
        SAMLSSOServiceProviderDTO[] serviceProviderSet1 = new SAMLSSOServiceProviderDTO[]{SP1, SP2, SP3};
        SAMLSSOServiceProviderDTO[] serviceProviderSet1pattern = new SAMLSSOServiceProviderDTO[]{SP2};
        SAMLSSOServiceProviderDTO[] serviceProviderSet2 = new SAMLSSOServiceProviderDTO[]{SP1, SP2, SP3, SP4, SP5, SP6};
        SAMLSSOServiceProviderDTO[] serviceProviderSet2pattern = new SAMLSSOServiceProviderDTO[]{SP2, SP5, SP6};

        return new Object[][]{
                {serviceProviderSet1,serviceProviderSet1pattern},
                {serviceProviderSet2,serviceProviderSet2pattern}};

    }

    @Test(dataProvider = "provideServiceProvider")
    public void testDoPaging(SAMLSSOServiceProviderDTO[] serviceProviderSet,SAMLSSOServiceProviderDTO[] serviceProviderSetpattern) throws Exception {
        SAMLSSOServiceProviderDTO[] returnServiceProviderSet = Util.doPaging(0, serviceProviderSet);
        Assert.assertTrue(assertSSOproviderArray(returnServiceProviderSet, serviceProviderSet));
    }

    @Test(dataProvider = "provideServiceProvider")
    public void testDoFilter(SAMLSSOServiceProviderDTO[] serviceProviderSet,SAMLSSOServiceProviderDTO[] serviceProviderSetpattern) throws Exception {
        SAMLSSOServiceProviderDTO[] returnServiceProviderSet = Util.doFilter("^([A-Za-z0-9+/])*=$",serviceProviderSet);
        Assert.assertTrue(assertSSOproviderArray(returnServiceProviderSet, serviceProviderSetpattern));
    }

    @Test
    public void testGetUserNameFromOpenID() throws Exception {
//        Util.getUserNameFromOpenID("https://localhost:9090/openid/abcd");
//        Util.getUserNameFromOpenID("/openid/abcd");

    }

    @Test
    public void testGetOpenID() throws Exception {
    }

    @Test
    public void testGenerateOpenID() throws Exception {
    }
    public boolean assertSSOproviderArray(SAMLSSOServiceProviderDTO[] actual, SAMLSSOServiceProviderDTO[] expected){
        for (int i = 0; i < actual.length; i++) {
            if (!actual[i].equals(expected[i])) {
                return false;
            }
        }
        return true;
    }



}