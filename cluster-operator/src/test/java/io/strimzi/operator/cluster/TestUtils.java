/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.ConfigMapKeySelectorBuilder;
import io.fabric8.kubernetes.api.model.Container;
import io.fabric8.kubernetes.api.model.EnvVar;
import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.common.metrics.JmxPrometheusExporterMetrics;
import io.strimzi.api.kafka.model.common.metrics.JmxPrometheusExporterMetricsBuilder;
import io.strimzi.operator.common.Util;
import io.strimzi.operator.common.model.Ca;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.singletonMap;

public class TestUtils {
    public static JmxPrometheusExporterMetrics getJmxPrometheusExporterMetrics(String key, String name) {
        return new JmxPrometheusExporterMetricsBuilder()
                .withNewValueFrom()
                    .withConfigMapKeyRef(new ConfigMapKeySelectorBuilder()
                            .withName(name)
                            .withKey(key)
                            .withOptional(true)
                            .build())
                .endValueFrom()
                .build();
    }

    public static ConfigMap getJmxMetricsCm(String data, String metricsCMName, String metricsConfigYaml) {
        return new ConfigMapBuilder()
                .withNewMetadata()
                .withName(metricsCMName)
                .endMetadata()
                .withData(singletonMap(metricsConfigYaml, data))
                .build();
    }

    /**
     * Gets the given container's environment as a Map. This makes it easier to verify the environment variables in
     * unit tests.
     *
     * @param container The container to retrieve the EnvVars from
     *
     * @return A map of the environment variables of the given container. The Environmental variable values indexed by
     * their names
     */
    public static Map<String, String> containerEnvVars(Container container) {
        return container.getEnv().stream().collect(
                Collectors.toMap(EnvVar::getName, EnvVar::getValue,
                        // On duplicates, last-in wins
                        (u, v) -> v));
    }

    /**
     * Extracts X509 certificate from a Kubernetes Secret
     *
     * @param secret    Kubernetes Secret with the certificate
     * @param key       Key under which the certificate is stored in the Secret
     *
     * @return  An X509Certificate instance with the certificate
     */
    public static X509Certificate cert(Secret secret, String key)  {
        if (secret == null || secret.getData() == null || secret.getData().get(key) == null) {
            return null;
        }
        byte[] bytes = Util.decodeBytesFromBase64(secret.getData().get(key));
        try {
            return Ca.x509Certificate(bytes);
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to decode certificate in data." + key.replace(".", "\\.") + " of Secret " + secret.getMetadata().getName(), e);
        }
    }

    public static Map<String, String> createInitialCaCert(String caCert, String caStore, String caStorePassword) {
        Map<String, String> certData = new HashMap<>();
        certData.put("ca.crt", caCert);
        certData.put("ca.p12", caStore);
        certData.put("ca.password", caStorePassword);
        return certData;
    }

    public static Map<String, String> createInitialCaKey(String caKey) {
        Map<String, String> keyData = new HashMap<>();
        keyData.put("ca.key", caKey);
        return keyData;
    }
}
