/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.api.kafka.model.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.strimzi.crdgenerator.annotations.Description;
import io.sundr.builder.annotations.Buildable;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Buildable(
        editableEnabled = false,
        builderPackage = Constants.FABRIC8_KUBERNETES_API
)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({ "type", "issuerRef" })
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class CertManagerCertificateIssuer extends CertificateIssuer {
    private IssuerRef issuerRef;
    @Description("Must be `" + TYPE_CERT_MANAGER + "`")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Override
    public String getType() {
        return TYPE_CERT_MANAGER;
    }

    @Description("The reference to the issuer. " +
            "Required")
    @JsonProperty(required = true)
    public IssuerRef getIssuerRef() {
        return issuerRef;
    }

    public void setIssuerRef(IssuerRef issuerRef) {
        this.issuerRef = issuerRef;
    }
}
