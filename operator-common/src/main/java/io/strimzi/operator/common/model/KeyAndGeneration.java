/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import io.fabric8.kubernetes.api.model.Secret;

/**
 * Represents a private key that is associated with a particular generation.
 * @param key Private key
 * @param generation Generation for the private key
 */
public record KeyAndGeneration(Secret key, int generation) {
}
