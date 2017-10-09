package org.wso2.carbon.identity.sso.saml.session;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.MockitoAnnotations.initMocks;

public class SSOSessionPersistenceManagerTest {

    private SSOSessionPersistenceManager ssoSessionPersistenceManager;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
        ssoSessionPersistenceManager = new SSOSessionPersistenceManager();
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testGetPersistenceManager() throws Exception {

        SSOSessionPersistenceManager persistenceManager = SSOSessionPersistenceManager.getPersistenceManager();
        Assert.assertNotNull(persistenceManager);

        SSOSessionPersistenceManager anotherPersistenceManager = SSOSessionPersistenceManager.getPersistenceManager();
        Assert.assertNotNull(anotherPersistenceManager);

        Assert.assertEquals(persistenceManager, anotherPersistenceManager);
    }

}