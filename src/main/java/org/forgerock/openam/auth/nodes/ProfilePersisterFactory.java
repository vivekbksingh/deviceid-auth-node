/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2014-2018 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.forgerock.openam.core.rest.devices.deviceprint.DeviceIdDao;

import java.util.Set;

/**
 * Generates a profile persister for for the provided realm/username.
 */
@Singleton
public class ProfilePersisterFactory {

    private final DeviceIdDao devicesDao;

    /**
     * Create a new ProfilePersisterFactory.
     *
     * @param devicesDao DeviceIdDao used to write data.
     */
    @Inject
    public ProfilePersisterFactory(DeviceIdDao devicesDao) {
        this.devicesDao = devicesDao;
    }

    /**
     * Generate a new ProfilePersister for the supplied username and realm with the provided maximum number of devices.
     *
     * @param max Max number of devices this user should have persisted.
     * @param username Username of the user.
     * @param realm Realm in which the user is operating.
     * @param userSearchAttributes Search alias attributes
     * @return a new ProfilePersister.
     */
    public ProfilePersister create(int max, String username, String realm, Set<String> userSearchAttributes) {
        return new ProfilePersister(max, username, realm, devicesDao, userSearchAttributes);
    }

}
