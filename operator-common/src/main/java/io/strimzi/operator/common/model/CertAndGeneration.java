/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import java.util.Map;

/**
 * Represents a public certificate that is associated with a particular generation.
 * @param certData Map of certificates
 * @param generation Generation for the public certificate
 */
public record CertAndGeneration(Map<String, String> certData, int generation) {
}
