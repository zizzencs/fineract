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

import com.google.common.base.Splitter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.fineract.infrastructure.core.config.FineractProperties;
import org.apache.fineract.infrastructure.security.exception.OidcUserNotFoundException;
import org.apache.fineract.organisation.office.domain.Office;
import org.apache.fineract.organisation.office.domain.OfficeRepository;
import org.apache.fineract.useradministration.domain.AppUser;
import org.apache.fineract.useradministration.domain.AppUserRepository;
import org.apache.fineract.useradministration.domain.Role;
import org.apache.fineract.useradministration.domain.RoleRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OidcAppUserResolutionServiceImpl implements OidcAppUserResolutionService {

    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private final OfficeRepository officeRepository;
    private final FineractProperties fineractProperties;

    // Stateless encoder — safe to create once per class
    private static final PasswordEncoder PASSWORD_ENCODER = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Override
    @Transactional
    public AppUser resolveOrCreate(String username, String email, String firstName, String lastName, Set<String> requestedRoles) {
        FineractProperties.FineractSecurityProperties.FineractSecurityOidcFederationProperties oidcConfig = fineractProperties.getSecurity()
                .getOidcFederation();

        // 1. Lookup by username
        AppUser user = appUserRepository.findAppUserByName(username);
        if (user != null) {
            log.debug("OIDC user resolved by username: '{}'", username);
            return synchronizeRoles(user, requestedRoles, oidcConfig);
        }

        // 2. Fallback: lookup by email
        if (email != null) {
            user = appUserRepository.findActiveUserByEmail(email);
            if (user != null) {
                log.debug("OIDC user resolved by email: '{}'", email);
                return synchronizeRoles(user, requestedRoles, oidcConfig);
            }
        }

        // 3. Auto-create when enabled
        if (!oidcConfig.isAutoCreateUser()) {
            log.warn("OIDC user '{}' not found in Fineract and auto-create is disabled", username);
            throw new OidcUserNotFoundException(username);
        }

        log.info("Auto-creating Fineract user for OIDC subject '{}'", username);
        return createUser(username, email, firstName, lastName, requestedRoles, oidcConfig);
    }

    /**
     * With a roles claim configured the token decides the user's roles whenever it is resolved to a user, which for a
     * Bearer token is every request: the default roles and the roles the token names. Without one, an existing user's
     * roles are left alone.
     *
     * A token that names the roles the user holds costs no query. Names the user does not hold are looked up with one
     * query: they are roles to add, or no Fineract roles at all.
     */
    private AppUser synchronizeRoles(AppUser user, Set<String> requestedRoles,
            FineractProperties.FineractSecurityProperties.FineractSecurityOidcFederationProperties oidcConfig) {
        if (oidcConfig.getRolesClaim() == null || oidcConfig.getRolesClaim().isBlank()) {
            return user;
        }
        Set<String> wanted = Stream.concat(Splitter.on(',').splitToList(oidcConfig.getDefaultRoles()).stream(), requestedRoles.stream())
                .map(String::trim).filter(name -> !name.isEmpty()).map(OidcAppUserResolutionServiceImpl::lowerCase)
                .collect(Collectors.toSet());
        Set<String> held = user.getRoles().stream().map(role -> lowerCase(role.getName())).collect(Collectors.toSet());

        Set<String> missing = new HashSet<>(wanted);
        missing.removeAll(held);
        List<Role> toAdd = missing.isEmpty() ? List.of() : roleRepository.findByLowerCaseNames(missing);
        if (toAdd.isEmpty() && wanted.containsAll(held)) {
            return user;
        }

        user.getRoles().removeIf(role -> !wanted.contains(lowerCase(role.getName())));
        user.getRoles().addAll(toAdd);
        log.info("Updated the roles of user '{}' from the OIDC token: {}", user.getUsername(),
                user.getRoles().stream().map(Role::getName).sorted().toList());
        return appUserRepository.saveAndFlush(user);
    }

    private static String lowerCase(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    private AppUser createUser(String username, String email, String firstName, String lastName, Set<String> requestedRoles,
            FineractProperties.FineractSecurityProperties.FineractSecurityOidcFederationProperties oidcConfig) {

        final Office headOffice = officeRepository.findById(fineractProperties.getDefaults().getOfficeId())
                .orElseThrow(() -> new IllegalStateException("Head office (id=1) not found — cannot auto-create OIDC user"));

        String encodedPassword = PASSWORD_ENCODER.encode(new RandomPasswordGenerator(20).generate());

        User springUser = new User(username, encodedPassword, true, true, true, true, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        Set<Role> roles = resolveRoles(oidcConfig.getDefaultRoles(), requestedRoles);

        String resolvedEmail = email != null ? email : username + "@oidc.placeholder";
        String resolvedFirstName = firstName != null ? firstName : username;
        String resolvedLastName = lastName != null ? lastName : "";

        AppUser appUser = new AppUser(headOffice, springUser, roles, resolvedEmail, resolvedFirstName, resolvedLastName, null, true, false);

        AppUser saved = appUserRepository.saveAndFlush(appUser);
        log.info("Auto-created Fineract user '{}' (id={}) from OIDC identity", username, saved.getId());
        return saved;
    }

    private Set<Role> resolveRoles(String defaultRolesConfig, Set<String> requestedRoles) {
        Set<Role> result = new HashSet<>();
        Stream.concat(Arrays.stream(defaultRolesConfig.split(",")), requestedRoles.stream()).map(String::trim)
                .filter(name -> !name.isEmpty()).forEach(name -> {
                    Role role = roleRepository.getRoleByName(name);
                    if (role != null) {
                        result.add(role);
                    } else {
                        log.warn("OIDC role mapping: role '{}' not found in Fineract — skipping", name);
                    }
                });
        return result;
    }
}
