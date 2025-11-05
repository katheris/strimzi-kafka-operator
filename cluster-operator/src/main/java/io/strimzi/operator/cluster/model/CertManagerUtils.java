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

    /**
     * Get the name of the Secret managed by Strimzi, given a cert-manager managed Secret
     *
     * @param certManagerSecretName Name of the Secret managed by cert-manager
     * @return Secret name to use for Strimzi managed Secret
     */
    public static String strimziSecretName(String certManagerSecretName) {
        if (!matchesCertManagerSecretNaming(certManagerSecretName)) {
            throw new RuntimeException("Supplied Secret does not match expected format for cert-manager Secret name");
        }
        return certManagerSecretName.substring(0, certManagerSecretName.length() - CERT_MANAGER_SECRET_SUFFIX.length());
    }

    /**
     * Returns whether the supplied Secret name has the same format as a Secret created by cert-manager
     *
     * @param secretName Secret name to check
     * @return Whether the Secret name matches the format of a Secret created by cert-manager
     */
    public static boolean matchesCertManagerSecretNaming(String secretName) {
        return secretName.endsWith(CERT_MANAGER_SECRET_SUFFIX);
    }
}
