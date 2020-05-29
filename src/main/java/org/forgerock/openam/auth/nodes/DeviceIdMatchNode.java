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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.rest.devices.DevicePersistenceException;
import org.forgerock.openam.core.rest.devices.deviceprint.DeviceIdDao;
import org.forgerock.openam.scripting.Script;
import org.forgerock.openam.scripting.ScriptConstants;
import org.forgerock.openam.scripting.service.ScriptConfiguration;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.util.Strings;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;

/**
 * A node to save the device print profile of the device they are using to
 * authenticate with
 */
@Node.Metadata(outcomeProvider = DeviceIdMatchNode.DeviceIdOutcomeProvider.class, configClass = DeviceIdMatchNode.Config.class)
public class DeviceIdMatchNode extends AbstractDecisionNode {
	private final Logger logger = LoggerFactory.getLogger(DeviceIdMatchNode.class);
	private final Config config;
	private Realm realm;

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		/**
         * The amount to increment/decrement the auth level.
         * @return the amount.
         */
        @Attribute(order = 100)
        @Script(ScriptConstants.AUTHENTICATION_CLIENT_SIDE_NAME)
        ScriptConfiguration script();
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
	public DeviceIdMatchNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
		this.config = config;
		this.realm = realm;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		logger.trace("DeviceIdMatchNode started");
		String userName = context.sharedState.get(USERNAME).asString();
		JsonValue newSharedState = context.sharedState.copy();
		List<JsonValue> devices;
		DeviceIdDao dao = InjectorHolder.getInstance(DeviceIdDao.class);
		AMIdentity userIdentity = IdUtils.getIdentity(userName, realm.asDN());
		try {
			if (userIdentity != null && userIdentity.isExists() && userIdentity.isActive()) {
				Optional<String> result = context.getCallback(HiddenValueCallback.class).map(HiddenValueCallback::getValue)
						.filter(deviceIdCollectScriptOutcome -> !Strings.isNullOrEmpty(deviceIdCollectScriptOutcome));
				if (result.isPresent()) {
					JsonValue clientDeviceProfileJson = JsonValueBuilder.toJsonValue(result.get());
					clientDeviceProfileJson.add("clientDeviceIpAddress", context.request.clientIp);
					newSharedState.put("clientDeviceProfile", clientDeviceProfileJson.toString());
					logger.trace("DeviceIdMatchNode : Client Script JSON : {}", clientDeviceProfileJson);

					devices = dao.getDeviceProfiles(userName, realm.asPath());
					logger.trace("DeviceIdMatchNode : Registered devices" + devices);
					if (devices.isEmpty()) {
						return Action.goTo("noRegisteredDevice").replaceSharedState(newSharedState).build();
					} else {
						newSharedState.put("devicesJsonList", devices);
						newSharedState.put("_DeviceIdDao", InjectorHolder.getInstance(DeviceIdDao.class));
						return Action.goTo("hasRegisteredDevice").replaceSharedState(newSharedState).build();
					}
				} else {
					logger.trace("DeviceIdMatchNode : getting user data and device data");
					String deviceIdMatchScript = createClientSideScriptExecutorFunction(config.script().getScript(), "deviceIdCollectScriptOutcome", true, context.sharedState.toString());
					ScriptTextOutputCallback scriptAndSelfSubmitCallback = new ScriptTextOutputCallback(deviceIdMatchScript);
					HiddenValueCallback hiddenValueCallback = new HiddenValueCallback("deviceIdCollectScriptOutcome");
					ImmutableList<Callback> callbacks = ImmutableList.of(scriptAndSelfSubmitCallback, hiddenValueCallback);
					return Action.send(callbacks).build();
				}
			}
			return Action.goTo("UserNotFound").build();
		} catch (DevicePersistenceException e) {
			logger.error("DeviceIdMatchNode : Error occured while collecting Device information for user name '{}' : {}", userName, e);
			return Action.goTo("Failure").replaceSharedState(newSharedState).build();
		} catch (SSOException | IdRepoException e) {
			logger.error("DeviceIdMatchNode : Error locating identity with user name '{}' : {}", userName, e);
			return Action.goTo("UserNotFound").replaceSharedState(newSharedState).build();
		} catch (Exception e) {
			logger.error("DeviceIdMatchNode : Error occured while collecting Device information for user name '{}' : {}", userName, e);
			throw new NodeProcessException("DeviceIdMatchNode : Error occured while collecting Device information for user name :" +  userName + ":" + e);
		}
	}

	public static String createClientSideScriptExecutorFunction(String script, String outputParameterId, boolean clientSideScriptEnabled, String context) {
        String collectingDataMessage = "";
        if (clientSideScriptEnabled) {
            collectingDataMessage = "    messenger.messages.addMessage( message );\n";
        }

        String spinningWheelScript = "if (window.require) {\n" +
                "    var messenger = require(\"org/forgerock/commons/ui/common/components/Messages\"),\n" +
                "        spinner =  require(\"org/forgerock/commons/ui/common/main/SpinnerManager\"),\n" +
                "        message =  {message:\"Collecting Data...\", type:\"info\"};\n" +
                "    spinner.showSpinner();\n" +
                collectingDataMessage +
                "}";

        return String.format(
                spinningWheelScript +
                        "(function(output) {\n" +
                        "    var autoSubmitDelay = 0,\n" +
                        "        submitted = false,\n" +
                        "        context = %s;\n" + //injecting context in form of JSON
                        "    function submit() {\n" +
                        "        if (submitted) {\n" +
                        "            return;\n" +
                        "        }" +
                        "        if (!(typeof $ == 'function')) {\n" + // Crude detection to see if XUI is not present.
                        "            document.getElementById('loginButton_0').click();\n" +
                        "        } else {\n" +
                        "            $('input[type=submit]').click();\n" +
                        "        }\n" +
                        "        submitted = true;\n" +
                        "    }\n" +
                        "    %s\n" + // script
                        "    setTimeout(submit, autoSubmitDelay);\n" +
                        "}) (document.forms[0].elements['%s']);\n", // outputParameterId
                context,
                script,
				outputParameterId);
	}

	/**
	 * Defines the possible outcomes from this node.
	 */
	public static class DeviceIdOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale("org/forgerock/openam/auth/nodes/DeviceIdMatchNode",
					DeviceIdMatchNode.DeviceIdOutcomeProvider.class.getClassLoader());

			ArrayList<Outcome> outcomes = new ArrayList<>();

			outcomes.add(new Outcome("Failure", bundle.getString("Failure")));
			outcomes.add(new Outcome("UserNotFound", bundle.getString("UserNotFound")));
			outcomes.add(new Outcome("hasRegisteredDevice", bundle.getString("hasRegisteredDevice")));
			outcomes.add(new Outcome("noRegisteredDevice", bundle.getString("noRegisteredDevice")));

			return ImmutableList.copyOf(outcomes);
		}
	}
}
