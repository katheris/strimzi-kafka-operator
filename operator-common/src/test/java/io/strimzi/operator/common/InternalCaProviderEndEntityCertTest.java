/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.model.CaConfig;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

//Moved from ClusterCaRenewalTest
public class InternalCaProviderEndEntityCertTest {
    private static final Map<String, Subject> SUBJECTS = Map.of(
            "pod0", new Subject.Builder().withCommonName("pod0").build(),
            "pod1", new Subject.Builder().withCommonName("pod1").build(),
            "pod2", new Subject.Builder().withCommonName("pod2").build());

    @Test
    public void renewalOfCertificatesWithNullCertificates() throws IOException {
        InternalCaProvider mockedCa = new MockedInternalCaProvider();

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                null,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert-pod0"));
        assertThat(new String(newCerts.get("pod0").key()), is("new-key-pod0"));
        assertThat(new String(newCerts.get("pod0").keyStore()), is("new-keystore-pod0"));
        assertThat(newCerts.get("pod0").storePassword(), is("new-password-pod0"));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert-pod1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key-pod1"));
        assertThat(new String(newCerts.get("pod1").keyStore()), is("new-keystore-pod1"));
        assertThat(newCerts.get("pod1").storePassword(), is("new-password-pod1"));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert-pod2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key-pod2"));
        assertThat(new String(newCerts.get("pod2").keyStore()), is("new-keystore-pod2"));
        assertThat(newCerts.get("pod2").storePassword(), is("new-password-pod2"));
    }

    @Test
    public void renewalOfCertificatesWithCaRenewal() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();
        mockedCa.setCaCertGeneration(1);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert-pod0"));
        assertThat(new String(newCerts.get("pod0").key()), is("new-key-pod0"));
        assertThat(new String(newCerts.get("pod0").keyStore()), is("new-keystore-pod0"));
        assertThat(newCerts.get("pod0").storePassword(), is("new-password-pod0"));
        assertThat(newCerts.get("pod0").caCertGeneration(), is(1));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert-pod1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key-pod1"));
        assertThat(new String(newCerts.get("pod1").keyStore()), is("new-keystore-pod1"));
        assertThat(newCerts.get("pod1").storePassword(), is("new-password-pod1"));
        assertThat(newCerts.get("pod1").caCertGeneration(), is(1));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert-pod2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key-pod2"));
        assertThat(new String(newCerts.get("pod2").keyStore()), is("new-keystore-pod2"));
        assertThat(newCerts.get("pod2").storePassword(), is("new-password-pod2"));
        assertThat(newCerts.get("pod2").caCertGeneration(), is(1));
    }

    @Test
    public void renewalOfCertificatesDelayedRenewalInWindow() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert-pod0"));
        assertThat(new String(newCerts.get("pod0").key()), is("new-key-pod0"));
        assertThat(new String(newCerts.get("pod0").keyStore()), is("new-keystore-pod0"));
        assertThat(newCerts.get("pod0").storePassword(), is("new-password-pod0"));
        assertThat(newCerts.get("pod0").caCertGeneration(), is(0));


        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert-pod1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key-pod1"));
        assertThat(new String(newCerts.get("pod1").keyStore()), is("new-keystore-pod1"));
        assertThat(newCerts.get("pod1").storePassword(), is("new-password-pod1"));
        assertThat(newCerts.get("pod1").caCertGeneration(), is(0));


        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert-pod2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key-pod2"));
        assertThat(new String(newCerts.get("pod2").keyStore()), is("new-keystore-pod2"));
        assertThat(newCerts.get("pod2").storePassword(), is("new-password-pod2"));
        assertThat(newCerts.get("pod2").caCertGeneration(), is(0));

    }

    @Test
    public void renewalOfCertificatesDelayedRenewalOutsideWindow() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = false;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod0").key()), is("old-key"));
        assertThat(newCerts.get("pod0").caCertGeneration(), is(0));


        assertThat(new String(newCerts.get("pod1").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod1").key()), is("old-key"));
        assertThat(newCerts.get("pod1").caCertGeneration(), is(0));


        assertThat(new String(newCerts.get("pod2").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod2").key()), is("old-key"));
        assertThat(newCerts.get("pod1").caCertGeneration(), is(0));

    }

    @Test
    public void renewalOfCertificatesWithNewNodesOutsideWindow() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = false;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod0").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod1").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod1").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert-pod2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key-pod2"));
    }

    @Test
    public void noRenewalOfCertificates() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                true,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod0").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod1").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod1").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod2").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod2").key()), is("old-key"));
    }

    @Test
    public void nosRenewalOfCertificatesWithScaleUp() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                true,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod0").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert-pod1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key-pod1"));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert-pod2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key-pod2"));
    }

    @Test
    public void noRenewalOfCertificatesWithScaleUpInTheMiddle() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                true,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod0").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert-pod1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key-pod1"));

        assertThat(new String(newCerts.get("pod2").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod2").key()), is("old-key"));
    }

    @Test
    public void noRenewalOfCertificatesScaleDown() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                Map.of("pod1", new Subject.Builder().withCommonName("pod1").build()),
                initialCerts,
                true,
                false
        );

        assertThat(newCerts.get("pod0"), is(nullValue()));

        assertThat(new String(newCerts.get("pod1").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod1").key()), is("old-key"));

        assertThat(newCerts.get("pod2"), is(nullValue()));
    }

    @Test
    public void changedSubjectOfCertificates() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert-pod0"));
        assertThat(new String(newCerts.get("pod0").key()), is("new-key-pod0"));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert-pod1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key-pod1"));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert-pod2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key-pod2"));
    }


    @Test
    public void certificatesIncludeCaChain() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                null,
                true,
                true
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert-pod0-CA-CERT"));
        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert-pod1-CA-CERT"));
        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert-pod2-CA-CERT"));
    }

    @Test
    public void caChainAddedToExistingCertificates() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("new-key-pod0".getBytes(), "new-cert-pod0".getBytes()));
        initialCerts.put("pod1", new CertAndKey("new-key-pod1".getBytes(), "new-cert-pod1".getBytes()));
        initialCerts.put("pod2", new CertAndKey("new-key-pod2".getBytes(), "new-cert-pod2".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                true,
                true
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert-pod0-CA-CERT"));
        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert-pod1-CA-CERT"));
        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert-pod2-CA-CERT"));
    }

    @Test
    public void testRenewalOfDeploymentCertificateWithNullCertAndKey() {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();

        CertAndKey newCert = mockedCa.maybeCopyOrGenerateClientCert(
                Reconciliation.DUMMY_RECONCILIATION,
                "pod0",
                null,
                true
        );

        assertThat(new String(newCert.cert()), is("new-cert-pod0"));
        assertThat(new String(newCert.key()), is("new-key-pod0"));
        assertThat(newCert.caCertGeneration(), is(0));
    }

    @Test
    public void testRenewalOfDeploymentCertificateWithRenewingCa() {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();
        mockedCa.setCaCertGeneration(1);

        CertAndKey initialCert = new CertAndKey("old-key".getBytes(), "old-cert".getBytes());

        CertAndKey newCert = mockedCa.maybeCopyOrGenerateClientCert(
                Reconciliation.DUMMY_RECONCILIATION,
                "pod0",
                initialCert,
                true
        );

        assertThat(new String(newCert.cert()), is("new-cert-pod0"));
        assertThat(new String(newCert.key()), is("new-key-pod0"));
        assertThat(newCert.caCertGeneration(), is(1));
    }

    @Test
    public void testRenewalOfDeploymentCertificateDelayedRenewal() {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();
        mockedCa.setCertExpiring(true);

        CertAndKey initialCert = new CertAndKey("old-key".getBytes(), "old-cert".getBytes());

        CertAndKey newCert = mockedCa.maybeCopyOrGenerateClientCert(
                Reconciliation.DUMMY_RECONCILIATION,
                "pod0",
                initialCert,
                true
        );

        assertThat(new String(newCert.cert()), is("new-cert-pod0"));
        assertThat(new String(newCert.key()), is("new-key-pod0"));
        assertThat(newCert.caCertGeneration(), is(0));
    }

    @Test
    public void testRenewalOfDeploymentCertificateDelayedRenewalOutsideOfMaintenanceWindow() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();
        mockedCa.setCertExpiring(true);

        CertAndKey initialCert = new CertAndKey("old-key".getBytes(), "old-cert".getBytes());

        CertAndKey newCert = mockedCa.maybeCopyOrGenerateClientCert(
                Reconciliation.DUMMY_RECONCILIATION,
                "pod0",
                initialCert,
                false
        );

        assertThat(new String(newCert.cert()), is("old-cert"));
        assertThat(new String(newCert.key()), is("old-key"));
        assertThat(newCert.caCertGeneration(), is(0));
    }

    //TODO what is this test for?
    @Test
    public void testHandlingOldSecretWithPKCS12Files() throws IOException {
        MockedInternalCaProvider mockedCa = new MockedInternalCaProvider();

        CertAndKey initialCert = new CertAndKey("old-key".getBytes(), "old-cert".getBytes(), null, "old-keystore".getBytes(), "old-password");

        CertAndKey newCert = mockedCa.maybeCopyOrGenerateClientCert(
                Reconciliation.DUMMY_RECONCILIATION,
                "deployment",
                initialCert,
                true
        );

        assertThat(new String(newCert.cert()), is("old-cert"));
        assertThat(new String(newCert.key()), is("old-key"));
        assertThat(new String(newCert.keyStore()), is("old-keystore"));
        assertThat(newCert.storePassword(), is("old-password"));
        assertThat(newCert.caCertGeneration(), is(0));
    }

    public static class MockedInternalCaProvider extends InternalCaProvider {
        private int caCertGeneration;
        private boolean isCertExpiring;

        public MockedInternalCaProvider() {
            super(Reconciliation.DUMMY_RECONCILIATION, null, null, null, null, null, null, CaConfig.createDefault());
        }

        @Override
        public byte[] currentCaCertBytes() {
            return "CA-CERT".getBytes();
        }

        @Override
        public boolean isExpiring(byte[] certificate)  {
            return isCertExpiring;
        }

        @Override
        protected boolean certSubjectChanged(CertAndKey certAndKey, Subject desiredSubject, String podName)    {
            // When differs from the default we use, we indicate change
            return !new Subject.Builder().withCommonName(podName).build().equals(desiredSubject);
        }

        @Override
        protected CertAndKey generateSignedCert(Subject subject,
                                                File csrFile, File keyFile, File certFile, File keyStoreFile, boolean includeCaChain) {
            String commonName = subject.commonName();
            byte[] cert;
            if (includeCaChain) {
                // Simulate concatenated chain: leaf + CA
                cert = ("new-cert-" + commonName + "-CA-CERT").getBytes();
            } else {
                cert = ("new-cert-" + commonName).getBytes();
            }

            return new CertAndKey(
                    ("new-key-" + commonName).getBytes(),
                    cert,
                    ("new-truststore-" + commonName).getBytes(),
                    ("new-keystore-" + commonName).getBytes(),
                    "new-password-" + commonName,
                    caCertGeneration
            );
        }

//        @Override
//        public CertAndKey addKeyAndCertToKeyStore(String alias, byte[] key, byte[] cert) {
//            int index = invocationCount.getAndIncrement();
//
//            return new CertAndKey(
//                    key,
//                    cert,
//                    ("new-truststore" + index).getBytes(),
//                    ("new-keystore" + index).getBytes(),
//                    "new-password" + index);
//        }

        @Override
        public int caCertGeneration() {
            return caCertGeneration;
        }

        public void setCertExpiring(boolean certExpiring) {
            isCertExpiring = certExpiring;
        }

        public void setCaCertGeneration(int value) {
            caCertGeneration = value;
        }
    }
}
