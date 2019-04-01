/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.sessionlimits;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.authentication.authenticators.sessionlimits.RealmSessionLimitsAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.UserBuilder;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class RealmSessionLimitsTest extends AbstractTestRealmKeycloakTest {

    @Deployment
    public static WebArchive deploy() {
        return RunOnServerDeployment.create(UserResource.class)
                .addPackages(true, "org.keycloak.testsuite");
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        UserRepresentation user = UserBuilder.create()
                .id("login-test")
                .username("login-test")
                .email("login@test.com")
                .enabled(true)
                .password("password")
                .build();
        RealmBuilder.edit(testRealm)
                .user(user);
    }

    @Before
    public void setupFlows() {

        testingClient.server().run(session -> {
            RealmModel realm = session.realms().getRealmByName("test");

            if (realm.getBrowserFlow().getAlias().equals("parent-flow")) {
                return;
            }
            // Parent flow
            AuthenticationFlowModel browser = new AuthenticationFlowModel();
            browser.setAlias("parent-flow");
            browser.setDescription("browser based authentication");
            browser.setProviderId("basic-flow");
            browser.setTopLevel(true);
            browser.setBuiltIn(true);
            browser = realm.addAuthenticationFlow(browser);
            realm.setBrowserFlow(browser);

            //  username password
            AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
            execution.setParentFlow(browser.getId());
            execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
            execution.setAuthenticator(UsernamePasswordFormFactory.PROVIDER_ID);
            execution.setPriority(20);
            execution.setAuthenticatorFlow(false);
            realm.addAuthenticatorExecution(execution);

            // session limits authenticator
            execution = new AuthenticationExecutionModel();
            execution.setParentFlow(browser.getId());
            execution.setRequirement(AuthenticationExecutionModel.Requirement.ALTERNATIVE);
            execution.setAuthenticator(RealmSessionLimitsAuthenticatorFactory.PROVIDER_ID);
            execution.setPriority(10);
            execution.setAuthenticatorFlow(false);

            AuthenticatorConfigModel configModel = new AuthenticatorConfigModel();
            Map<String, String> sessionAuthenticatorConfig = new HashMap<>();
            sessionAuthenticatorConfig.put(RealmSessionLimitsAuthenticatorFactory.BEHAVIOR, RealmSessionLimitsAuthenticatorFactory.DENY_NEW_SESSION);
            sessionAuthenticatorConfig.put(RealmSessionLimitsAuthenticatorFactory.REALM_LIMIT, "1");
            configModel.setConfig(sessionAuthenticatorConfig);
            configModel.setAlias("realm-session-limits");
            configModel = realm.addAuthenticatorConfig(configModel);
            execution.setAuthenticatorConfig(configModel.getId());
            realm.addAuthenticatorExecution(execution);
        });
    }

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Page
    protected LoginPage loginPage;

    @Test
    public void testSessionCreationAllowed() {
        String loginFormUrl = oauth.getLoginFormUrl();
        driver.navigate().to(loginFormUrl);
        loginPage.assertCurrent();
    }

    @Test
    public void testSessionCountExceededAndNewSessionDenied() {
        // Perform a successful login, so the session count will be 1.
        // Any subsequent request for the login page should be denied.
        loginPage.open();
        loginPage.login("login-test", "password");

        // Now request the login page and expect a 403.
        Client clientThatShouldBeDenied = ClientBuilder.newClient();
        Response response2 = clientThatShouldBeDenied.target(oauth.getLoginFormUrl()).request().get();
        Assert.assertThat(response2.getStatus(), is(equalTo(403)));
    }

}
