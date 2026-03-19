/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

import io.strimzi.operator.common.model.Ca;

import java.util.Map;

public record CaData(Ca.RenewalType renewalType,
                     int caCertGeneration,
                     Map<String, String> caCertData,
                     int caKeyGeneration,
                     Map<String, String> caKeyData,
                     boolean caCertsRemoved) {
}
