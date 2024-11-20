/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.api.kafka.model.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import io.strimzi.crdgenerator.annotations.Description;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.HashMap;
import java.util.Map;

/**
 * Abstract baseclass for different representations of certificate issuer, discriminated by {@link #getType() type}.
 */
@Description("Configuration of issuer for TLS certificates. " +
        "This is optional and defaults to `internal` if not specified.")
@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.EXISTING_PROPERTY,
        property = "type"
)
@JsonSubTypes(
    {
        @JsonSubTypes.Type(value = InternalCertificateIssuer.class, name = CertificateIssuer.TYPE_INTERNAL),
        @JsonSubTypes.Type(value = CertManagerCertificateIssuer.class, name = CertificateIssuer.TYPE_CERT_MANAGER)
    }
)
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
@EqualsAndHashCode
@ToString
public abstract class CertificateIssuer implements UnknownPropertyPreserving {
    public static final String TYPE_INTERNAL = "internal";
    public static final String TYPE_CERT_MANAGER = "cert-manager.io";
    private Map<String, Object> additionalProperties;

    @Description("The type of issuer. " +
            "The available types are `internal` and `cert-manager.io`. " +
            "Required.")
    public abstract String getType();

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
