# CertManagerST

**Description:** Test suite verifying cert-manager CA integration: The Cluster Operator delegates issuing of end-entity certificate to an external cert-manager issuer while the cluster CA public cert is provided by the user in a Kubernetes Secret.

**Labels:**

* [security](labels/security.md)

<hr style="border:1px solid">

## testNewClusterWithCertManagerClusterCa

**Description:** Verifies the cert-manager Cluster CA happy path: a new Kafka cluster is deployed with clusterCa.type=cert-manager.io. cert-manager issues all component end-entity certificates. The cluster must come up healthy and a TLS-authenticated producer/consumer must be able to send and receive messages.

**Steps:**

| Step | Action | Result |
| - | - | - |
| 1. | Create the CA cert Secret in the test namespace. | Secret is present in the test namespace. |
| 2. | Deploy Kafka with clusterCa.type=cert-manager.io, generateCertificateAuthority=false. | Kafka cluster reaches ready state without errors. |
| 3. | Assert cluster CA cert Secret has correct annotations. | ca-cert-generation=0, ca-key-generation=0, and cert-hash annotations are set. |
| 4. | Assert the cert-manager broker and cluster operator Secrets (-cm suffix) exist and their certificates match the corresponding Strimzi Secrets and are signed by the cert-manager CA. | cert-manager Secrets exist, their certificates match the Strimzi Secrets, and the issuer DNs match the CA subject DN. |
| 5. | Produce and consume messages over TLS using a KafkaUser. | Messages are successfully produced and consumed. |

**Labels:**

* [security](labels/security.md)

