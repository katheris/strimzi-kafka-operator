/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.model;

import io.strimzi.certs.CertAndKey;

/**
 * Represents a public certificate and private key pair that is associated with a particular generation.
 * @param certAndKey Public certificate and private key pair
 * @param generation Generation for the public certificate and private key pair
 */
public record CertAndKeyWithGeneration(CertAndKey certAndKey, int generation) {
}
