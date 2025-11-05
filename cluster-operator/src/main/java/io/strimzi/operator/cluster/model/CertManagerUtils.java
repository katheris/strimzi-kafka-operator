/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.model;

/**
 * cert-manager utility methods
 */
public class CertManagerUtils {
    private static final String CERT_MANAGER_SECRET_SUFFIX = "-cm";
    /**
     * Get the name of the Secret managed by cert-manager, given a Strimzi managed Secret
     *
     * @param strimziSecretName Name of the Secret managed by Strimzi
     * @return Secret name to use for cert-manager managed Secret
     */
    public static String certManagerSecretName(String strimziSecretName) {
        return strimziSecretName + CERT_MANAGER_SECRET_SUFFIX;
    }
}
