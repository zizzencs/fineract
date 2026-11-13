/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.fineract.infrastructure.security.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.fineract.infrastructure.core.config.FineractProperties;
import org.apache.fineract.infrastructure.core.config.FineractProperties.FineractSecurityProperties;
import org.apache.fineract.infrastructure.core.config.FineractProperties.FineractSecurityProperties.FineractSecurityOidcFederationProperties;
import org.apache.fineract.useradministration.domain.AppUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.jwt.Jwt;

class FineractOidcUserServiceTest {

    private final FineractSecurityOidcFederationProperties oidcProperties = new FineractSecurityOidcFederationProperties();
    private final OidcAppUserResolutionService resolutionService = mock(OidcAppUserResolutionService.class);
    private FineractOidcUserService service;

    @BeforeEach
    void setUp() {
        FineractSecurityProperties securityProperties = new FineractSecurityProperties();
        securityProperties.setOidcFederation(oidcProperties);
        FineractProperties fineractProperties = new FineractProperties();
        fineractProperties.setSecurity(securityProperties);
        service = new FineractOidcUserService(resolutionService, fineractProperties);
    }

    @Test
    void noRolesWithoutRolesClaimConfigured() {
        assertThat(service.extractRoles(jwt("roles", List.of("Teller")))).isEmpty();
    }

    @Test
    void rolesFromListClaim() {
        oidcProperties.setRolesClaim("roles");

        assertThat(service.extractRoles(jwt("roles", List.of("Teller", "Branch Manager")))).containsExactly("Teller", "Branch Manager");
    }

    @Test
    void rolesFromCommaSeparatedClaim() {
        oidcProperties.setRolesClaim("roles");

        assertThat(service.extractRoles(jwt("roles", "Teller, Branch Manager,"))).containsExactly("Teller", "Branch Manager");
    }

    @Test
    void rolesFromNestedClaim() {
        oidcProperties.setRolesClaim("realm_access.roles");

        assertThat(service.extractRoles(jwt("realm_access", Map.of("roles", List.of("Teller"))))).containsExactly("Teller");
    }

    @Test
    void literalClaimNameWinsOverNestedPath() {
        oidcProperties.setRolesClaim("https://example.com/roles.v1");

        assertThat(service.extractRoles(jwt("https://example.com/roles.v1", List.of("Teller")))).containsExactly("Teller");
    }

    @Test
    void noRolesWhenTheTokenLacksTheClaim() {
        oidcProperties.setRolesClaim("realm_access.roles");

        assertThat(service.extractRoles(jwt("other", "x"))).isEmpty();
    }

    @Test
    void resolveUserPassesTheRolesOfTheToken() {
        oidcProperties.setRolesClaim("roles");
        Jwt jwt = jwt("roles", List.of("Teller"));
        AppUser appUser = mock(AppUser.class);
        when(resolutionService.resolveOrCreate(any(), any(), any(), any(), any())).thenReturn(appUser);

        assertThat(service.resolveUser(jwt, "alice")).isSameAs(appUser);
        verify(resolutionService).resolveOrCreate("alice", null, null, null, Set.of("Teller"));
    }

    @Test
    void resolvesAgainAfterAConcurrentWrite() {
        Jwt jwt = jwt("roles", List.of("Teller"));
        AppUser appUser = mock(AppUser.class);
        when(resolutionService.resolveOrCreate(any(), any(), any(), any(), any()))
                .thenThrow(new DataIntegrityViolationException("duplicate key")).thenReturn(appUser);

        assertThat(service.resolveUser(jwt, "alice")).isSameAs(appUser);
        verify(resolutionService, times(2)).resolveOrCreate("alice", null, null, null, Set.of());
    }

    @Test
    void givesUpAfterASecondFailure() {
        Jwt jwt = jwt("roles", List.of("Teller"));
        when(resolutionService.resolveOrCreate(any(), any(), any(), any(), any()))
                .thenThrow(new DataIntegrityViolationException("duplicate key"));

        assertThatThrownBy(() -> service.resolveUser(jwt, "alice")).isInstanceOf(DataIntegrityViolationException.class);
        verify(resolutionService, times(2)).resolveOrCreate(any(), any(), any(), any(), any());
    }

    private static Jwt jwt(String claim, Object value) {
        return Jwt.withTokenValue("token").header("alg", "RS256").subject("sub-123").claim(claim, value).issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300)).build();
    }
}
