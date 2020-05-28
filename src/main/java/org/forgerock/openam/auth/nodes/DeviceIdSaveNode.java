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
 * Copyright 2017-2018 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.utils.Time.currentTimeMillis;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.NameCallback;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node to save the device print profile of the device they are using to
 * authenticate with
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = DeviceIdSaveNode.Config.class)
public class DeviceIdSaveNode extends AbstractDecisionNode {
	private static final String OPTION_NO = "NO";
	private static final String OPTION_YES = "YES";
	private static final String ADD_TO_TRUSTED_DEVICES = "Add to Trusted Devices?";
	private static final String TRUSTED_DEVICE_NAME = "Trusted Device Name?";
	private final Logger logger = LoggerFactory.getLogger(DeviceIdSaveNode.class);
	private final Config config;

	private Set<String> userSearchAttributes = Collections.emptySet();
	private Realm realm;

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		@Attribute(order = 100)
		default boolean autoStoreProfiles() {
			return false;
		}

		@Attribute(order = 300, validators = { RequiredValueValidator.class })
		default int maxProfilesAllowed() {
			return 5;
		}
	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config
	 *            The service config.
	 * @param realm
	 *            The realm the node is in.
	 * @throws NodeProcessException
	 *             If the configuration was not valid.
	 */
	@Inject
	public DeviceIdSaveNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
		this.config = config;
		this.realm = realm;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		ProfilePersisterFactory profilePersisterFactory = InjectorHolder.getInstance(ProfilePersisterFactory.class);
		String userName = context.sharedState.get(USERNAME).asString();
		String clientDeviceProfile = context.sharedState.get("clientDeviceProfile").asString();
		AMIdentity userIdentity = IdUtils.getIdentity(userName, realm.asDN());
		try {
			if (userIdentity != null && userIdentity.isExists() && userIdentity.isActive()) {
				try {
					Map<String, Object> devicePrintProfile = JsonValueBuilder.getObjectMapper().readValue(clientDeviceProfile, Map.class);
					
					ProfilePersister profilePersister = profilePersisterFactory.create(config.maxProfilesAllowed(), userName, realm.asPath(), userSearchAttributes);
					if (devicePrintProfile == null || devicePrintProfile.isEmpty()) {
						return goTo(false).build();
					} else if (config.autoStoreProfiles()) {
						profilePersister.saveDevicePrint(devicePrintProfile);
					} else {
						if (context.hasCallbacks() && context.getCallback(NameCallback.class).isPresent()) {
							NameCallback nameCallback = context.getCallback(NameCallback.class).get();
							String name = nameCallback.getName();
							profilePersister.saveDevicePrint(name, devicePrintProfile);
						} else if (context.hasCallbacks() && context.getCallback(ChoiceCallback.class).isPresent()) {
							ChoiceCallback choiceCallback = context.getCallback(ChoiceCallback.class).get();
							if (choiceCallback.getSelectedIndexes()[0] == 0) {
								return Action.send(new NameCallback(TRUSTED_DEVICE_NAME)).build();
							}
						} else {
							return Action.send(new ChoiceCallback(ADD_TO_TRUSTED_DEVICES, new String[]{ OPTION_YES, OPTION_NO }, 1, false)).build();
						}
					}
					return goTo(true).build();
				} catch (IOException | AuthLoginException e) {
					logger.error("DeviceIdSaveNode : Error while saving device profile for username {}. Exception : {}", userName, e);
					throw new NodeProcessException(String.format("DeviceIdSaveNode : Error while saving device profile for username {}. Exception : {}", userName, e));
				}
			} else {
				logger.error("DeviceIdSaveNode : Unable to find identity for user name : '{}'", userName);
				throw new NodeProcessException("DeviceIdSaveNode : Unable to find identity for user name : " + userName);
			}
		} catch (IdRepoException | SSOException e) {
			logger.error("DeviceIdSaveNode : Error locating identity with user name '{}' : {}", userName, e);
			throw new NodeProcessException(String.format("DeviceIdSaveNode : Error locating identity with user name {} : {}", userName, e));
		}
	}
}
