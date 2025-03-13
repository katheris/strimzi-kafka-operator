/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.api.kafka.model.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.strimzi.api.kafka.model.common.certmanager.CertManager;
import io.strimzi.crdgenerator.annotations.Description;
import io.strimzi.crdgenerator.annotations.Minimum;
import io.sundr.builder.annotations.Buildable;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.HashMap;
import java.util.Map;

@Description("Configuration of how TLS certificates are used within the cluster. " +
        "This applies to certificates used for both internal communication within the cluster and to certificates " +
        "used for client access via `Kafka.spec.kafka.listeners.tls`.")
@Buildable(
        editableEnabled = false,
        builderPackage = Constants.FABRIC8_KUBERNETES_API
)
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
@JsonPropertyOrder({ "generateCertificateAuthority", "type", "generateSecretOwnerReference", "validityDays",
    "renewalDays", "certificateExpirationPolicy", "certManager" })
@EqualsAndHashCode
@ToString
public class CertificateAuthority implements UnknownPropertyPreserving {
    public static final int DEFAULT_CERTS_VALIDITY_DAYS = 365;
    public static final int DEFAULT_CERTS_RENEWAL_DAYS = 30;
    
    private int validityDays;
    private boolean generateCertificateAuthority = true;
    private CertificateManagerType type = CertificateManagerType.STRIMZI_IO;
    private boolean generateSecretOwnerReference = true;
    private int renewalDays;
    private CertificateExpirationPolicy certificateExpirationPolicy;
    private CertManager certManager;
    private Map<String, Object> additionalProperties;

    @Description("The number of days generated certificates should be valid for. The default is 365.")
    @Minimum(1)
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public int getValidityDays() {
        return validityDays;
    }

    public void setValidityDays(int validityDays) {
        this.validityDays = validityDays;
    }

    @Description("If true then Certificate Authority certificates will be generated automatically. " +
            "Otherwise the user will need to provide a Secret with the CA certificate. " +
            "Default is true.")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public boolean isGenerateCertificateAuthority() {
        return generateCertificateAuthority;
    }

    public void setGenerateCertificateAuthority(boolean generateCertificateAuthority) {
        this.generateCertificateAuthority = generateCertificateAuthority;
    }

    @Description("The type of certificate manager. " +
            "The available types are `strimzi.io` and `cert-manager.io`. " +
            "Default is `strimzi.io`")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public CertificateManagerType getType() {
        return type;
    }

    public void setType(CertificateManagerType type) {
        this.type = type;
    }

    @Description("If `true`, the Cluster and Client CA Secrets are configured with the `ownerReference` set to the `Kafka` resource. " +
            "If the `Kafka` resource is deleted when `true`, the CA Secrets are also deleted. " +
            "If `false`, the `ownerReference` is disabled. " +
            "If the `Kafka` resource is deleted when `false`, the CA Secrets are retained and available for reuse. " +
            "Default is `true`.")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public boolean isGenerateSecretOwnerReference() {
        return generateSecretOwnerReference;
    }

    public void setGenerateSecretOwnerReference(boolean generateSecretOwnerReference) {
        this.generateSecretOwnerReference = generateSecretOwnerReference;
    }

    @Description("The number of days in the certificate renewal period. " +
            "This is the number of days before the a certificate expires during which renewal actions may be performed. " +
            "When `generateCertificateAuthority` is true, this will cause the generation of a new certificate. " +
            "When `generateCertificateAuthority` is true, this will cause extra logging at WARN level about the pending certificate expiry. " +
            "Default is 30.")
    @Minimum(1)
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public int getRenewalDays() {
        return renewalDays;
    }

    public void setRenewalDays(int renewalDays) {
        this.renewalDays = renewalDays;
    }

    @Description("How should CA certificate expiration be handled when `generateCertificateAuthority=true`. " +
            "The default is for a new CA certificate to be generated reusing the existing private key.")
    public CertificateExpirationPolicy getCertificateExpirationPolicy() {
        return certificateExpirationPolicy;
    }

    public void setCertificateExpirationPolicy(CertificateExpirationPolicy certificateExpirationPolicy) {
        this.certificateExpirationPolicy = certificateExpirationPolicy;
    }

    @Description("Configuration for using cert-manager to issue certificates. " +
            "This only applies if the CA type is set to `cert-manager.io`.")
    public CertManager getCertManager() {
        return certManager;
    }

    public void setCertManager(CertManager certManager) {
        this.certManager = certManager;
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
