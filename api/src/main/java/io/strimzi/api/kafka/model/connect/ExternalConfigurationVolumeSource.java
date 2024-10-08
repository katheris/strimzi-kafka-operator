/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.api.kafka.model.connect;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.fabric8.kubernetes.api.model.ConfigMapVolumeSource;
import io.fabric8.kubernetes.api.model.SecretVolumeSource;
import io.strimzi.api.annotations.DeprecatedType;
import io.strimzi.api.kafka.model.common.Constants;
import io.strimzi.api.kafka.model.common.UnknownPropertyPreserving;
import io.strimzi.api.kafka.model.common.template.AdditionalVolume;
import io.strimzi.crdgenerator.annotations.Description;
import io.strimzi.crdgenerator.annotations.KubeLink;
import io.strimzi.crdgenerator.annotations.OneOf;
import io.sundr.builder.annotations.Buildable;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.HashMap;
import java.util.Map;

/**
 * Representation for environment variables which will be passed to Kafka Connect
 */
@Buildable(
        editableEnabled = false,
        builderPackage = Constants.FABRIC8_KUBERNETES_API
)
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
@JsonPropertyOrder({"name", "secret", "configMap"})
@OneOf({@OneOf.Alternative(@OneOf.Alternative.Property("secret")), @OneOf.Alternative(@OneOf.Alternative.Property("configMap"))})
@Deprecated
@DeprecatedType(replacedWithType = AdditionalVolume.class)
@EqualsAndHashCode
@ToString
public class ExternalConfigurationVolumeSource implements UnknownPropertyPreserving {
    private String name;
    private SecretVolumeSource secret;
    private ConfigMapVolumeSource configMap;
    private Map<String, Object> additionalProperties;

    @Description("Name of the volume which will be added to the Kafka Connect pods.")
    @JsonProperty(required = true)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Description("Reference to a key in a Secret. " +
            "Exactly one Secret or ConfigMap has to be specified.")
    @KubeLink(group = "core", version = "v1", kind = "secretvolumesource")
    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    public SecretVolumeSource getSecret() {
        return secret;
    }

    public void setSecret(SecretVolumeSource secret) {
        this.secret = secret;
    }

    @Description("Reference to a key in a ConfigMap. " +
            "Exactly one Secret or ConfigMap has to be specified.")
    @KubeLink(group = "core", version = "v1", kind = "configmapvolumesource")
    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    public ConfigMapVolumeSource getConfigMap() {
        return configMap;
    }

    public void setConfigMap(ConfigMapVolumeSource configMap) {
        this.configMap = configMap;
    }

    @Override
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties != null ? this.additionalProperties : Map.of();
    }

    @Override
    public void setAdditionalProperty(String name, Object value) {
        if (this.additionalProperties == null) {
            this.additionalProperties = new HashMap<>(2);
        }
        this.additionalProperties.put(name, value);
    }
}
