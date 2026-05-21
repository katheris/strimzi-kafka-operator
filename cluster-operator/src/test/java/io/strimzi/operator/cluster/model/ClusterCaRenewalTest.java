/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.model;

import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.Reconciliation;
import io.vertx.junit5.VertxExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

@ExtendWith(VertxExtension.class)
public class ClusterCaRenewalTest {
    private static final Subject SUBJECT = new Subject.Builder().build();
    private static final Map<String, Subject> SUBJECT_MAP = new LinkedHashMap<>();
    // LinkedHashMap is used to maintain ordering and have predictable test results
    static {
        SUBJECT_MAP.put("pod0", SUBJECT);
        SUBJECT_MAP.put("pod1", SUBJECT);
        SUBJECT_MAP.put("pod2", SUBJECT);
    }

    @Test
    public void renewalOfCertificatesWithNullCertificates() throws IOException {
        ClusterCa mockedCa = new MockedClusterCa();

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
                null,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert0"));
        assertThat(new String(newCerts.get("pod0").key()), is("new-key0"));
        assertThat(new String(newCerts.get("pod0").keyStore()), is("new-keystore0"));
        assertThat(newCerts.get("pod0").storePassword(), is("new-password0"));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key1"));
        assertThat(new String(newCerts.get("pod1").keyStore()), is("new-keystore1"));
        assertThat(newCerts.get("pod1").storePassword(), is("new-password1"));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key2"));
        assertThat(new String(newCerts.get("pod2").keyStore()), is("new-keystore2"));
        assertThat(newCerts.get("pod2").storePassword(), is("new-password2"));
    }

    @Test
    public void renewalOfCertificatesWithCaRenewal() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();
        mockedCa.setCaCertGeneration(1);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert0"));
        assertThat(new String(newCerts.get("pod0").key()), is("new-key0"));
        assertThat(new String(newCerts.get("pod0").keyStore()), is("new-keystore0"));
        assertThat(newCerts.get("pod0").storePassword(), is("new-password0"));
        assertThat(newCerts.get("pod0").caCertGeneration(), is(1));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key1"));
        assertThat(new String(newCerts.get("pod1").keyStore()), is("new-keystore1"));
        assertThat(newCerts.get("pod1").storePassword(), is("new-password1"));
        assertThat(newCerts.get("pod1").caCertGeneration(), is(1));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key2"));
        assertThat(new String(newCerts.get("pod2").keyStore()), is("new-keystore2"));
        assertThat(newCerts.get("pod2").storePassword(), is("new-password2"));
        assertThat(newCerts.get("pod2").caCertGeneration(), is(1));
    }

    @Test
    public void renewalOfCertificatesDelayedRenewalInWindow() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert0"));
        assertThat(new String(newCerts.get("pod0").key()), is("new-key0"));
        assertThat(new String(newCerts.get("pod0").keyStore()), is("new-keystore0"));
        assertThat(newCerts.get("pod0").storePassword(), is("new-password0"));
        assertThat(newCerts.get("pod0").caCertGeneration(), is(0));


        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key1"));
        assertThat(new String(newCerts.get("pod1").keyStore()), is("new-keystore1"));
        assertThat(newCerts.get("pod1").storePassword(), is("new-password1"));
        assertThat(newCerts.get("pod1").caCertGeneration(), is(0));


        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key2"));
        assertThat(new String(newCerts.get("pod2").keyStore()), is("new-keystore2"));
        assertThat(newCerts.get("pod2").storePassword(), is("new-password2"));
        assertThat(newCerts.get("pod2").caCertGeneration(), is(0));

    }

    @Test
    public void renewalOfCertificatesDelayedRenewalOutsideWindow() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        
        boolean isMaintenanceTimeWindowsSatisfied = false;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
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
        MockedClusterCa mockedCa = new MockedClusterCa();
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = false;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod0").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod1").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod1").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert0"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key0"));
    }

    @Test
    public void noRenewalOfCertificates() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
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
        MockedClusterCa mockedCa = new MockedClusterCa();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
                initialCerts,
                true,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod0").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert0"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key0"));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert1"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key1"));
    }

    @Test
    public void noRenewalOfCertificatesWithScaleUpInTheMiddle() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
                initialCerts,
                true,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod0").key()), is("old-key"));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert0"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key0"));

        assertThat(new String(newCerts.get("pod2").cert()), is("old-cert"));
        assertThat(new String(newCerts.get("pod2").key()), is("old-key"));
    }

    @Test
    public void noRenewalOfCertificatesScaleDown() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                Map.of("pod1", SUBJECT),
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
        MockedClusterCa mockedCa = new MockedClusterCa();
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, Subject> subjectMap = new LinkedHashMap<>();
        // LinkedHashMap is used to maintain ordering and have predictable test results
        subjectMap.put("pod0", new Subject.Builder().withCommonName("pod0").build());
        subjectMap.put("pod1", new Subject.Builder().withCommonName("pod1").build());
        subjectMap.put("pod2", new Subject.Builder().withCommonName("pod2").build());

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                subjectMap,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied,
                false
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert0"));
        assertThat(new String(newCerts.get("pod0").key()), is("new-key0"));

        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert1"));
        assertThat(new String(newCerts.get("pod1").key()), is("new-key1"));

        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert2"));
        assertThat(new String(newCerts.get("pod2").key()), is("new-key2"));
    }


    @Test
    public void certificatesIncludeCaChain() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
                null,
                true,
                true
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert0CA-CERT"));
        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert1CA-CERT"));
        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert2CA-CERT"));
    }

    @Test
    public void caChainAddedToExistingCertificates() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("new-key0".getBytes(), "new-cert0".getBytes()));
        initialCerts.put("pod1", new CertAndKey("new-key1".getBytes(), "new-cert1".getBytes()));
        initialCerts.put("pod2", new CertAndKey("new-key2".getBytes(), "new-cert2".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateServerCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECT_MAP,
                initialCerts,
                true,
                true
        );

        assertThat(new String(newCerts.get("pod0").cert()), is("new-cert0CA-CERT"));
        assertThat(new String(newCerts.get("pod1").cert()), is("new-cert1CA-CERT"));
        assertThat(new String(newCerts.get("pod2").cert()), is("new-cert2CA-CERT"));
    }

    @Test
    public void testRenewalOfDeploymentCertificateWithNullCertAndKey() {
        MockedClusterCa mockedCa = new MockedClusterCa();

        CertAndKey newCert = mockedCa.maybeCopyOrGenerateClientCert(
                Reconciliation.DUMMY_RECONCILIATION,
                "deployment",
                null,
                true
        );

        assertThat(new String(newCert.cert()), is("new-cert0"));
        assertThat(new String(newCert.key()), is("new-key0"));
        assertThat(newCert.caCertGeneration(), is(0));
    }

    @Test
    public void testRenewalOfDeploymentCertificateWithRenewingCa() {
        MockedClusterCa mockedCa = new MockedClusterCa();
        mockedCa.setCaCertGeneration(1);

        CertAndKey initialCert = new CertAndKey("old-key".getBytes(), "old-cert".getBytes());

        CertAndKey newCert = mockedCa.maybeCopyOrGenerateClientCert(
                Reconciliation.DUMMY_RECONCILIATION,
                "deployment",
                initialCert,
                true
        );

        assertThat(new String(newCert.cert()), is("new-cert0"));
        assertThat(new String(newCert.key()), is("new-key0"));
        assertThat(newCert.caCertGeneration(), is(1));
    }

    @Test
    public void testRenewalOfDeploymentCertificateDelayedRenewal() {
        MockedClusterCa mockedCa = new MockedClusterCa();
        mockedCa.setCertExpiring(true);

        CertAndKey initialCert = new CertAndKey("old-key".getBytes(), "old-cert".getBytes());

        CertAndKey newCert = mockedCa.maybeCopyOrGenerateClientCert(
                Reconciliation.DUMMY_RECONCILIATION,
                "deployment",
                initialCert,
                true
        );

        assertThat(new String(newCert.cert()), is("new-cert0"));
        assertThat(new String(newCert.key()), is("new-key0"));
        assertThat(newCert.caCertGeneration(), is(0));
    }

    @Test
    public void testRenewalOfDeploymentCertificateDelayedRenewalOutsideOfMaintenanceWindow() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();
        mockedCa.setCertExpiring(true);

        CertAndKey initialCert = new CertAndKey("old-key".getBytes(), "old-cert".getBytes());

        CertAndKey newCert = mockedCa.maybeCopyOrGenerateClientCert(
                Reconciliation.DUMMY_RECONCILIATION,
                "deployment",
                initialCert,
                false
        );

        assertThat(new String(newCert.cert()), is("old-cert"));
        assertThat(new String(newCert.key()), is("old-key"));
        assertThat(newCert.caCertGeneration(), is(0));
    }

    @Test
    public void testHandlingOldSecretWithPKCS12Files() throws IOException {
        MockedClusterCa mockedCa = new MockedClusterCa();

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

    public static class MockedClusterCa extends ClusterCa {
        private final AtomicInteger invocationCount = new AtomicInteger(0);
        private int caCertGeneration;
        private boolean isCertExpiring;

        public MockedClusterCa() {
            super(Reconciliation.DUMMY_RECONCILIATION, null, null, null, null);
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
            return !new Subject.Builder().build().equals(desiredSubject);
        }

        @Override
        protected CertAndKey generateSignedCert(Subject subject,
                                                File csrFile, File keyFile, File certFile, File keyStoreFile, boolean includeCaChain) {
            int index = invocationCount.getAndIncrement();

            byte[] cert;
            if (includeCaChain) {
                // Simulate concatenated chain: leaf + CA
                cert = ("new-cert" + index + "CA-CERT").getBytes();
            } else {
                cert = ("new-cert" + index).getBytes();
            }

            return new CertAndKey(
                    ("new-key" + index).getBytes(),
                    cert,
                    ("new-truststore" + index).getBytes(),
                    ("new-keystore" + index).getBytes(),
                    "new-password" + index,
                    caCertGeneration
            );
        }

        @Override
        public CertAndKey addKeyAndCertToKeyStore(String alias, byte[] key, byte[] cert) {
            int index = invocationCount.getAndIncrement();

            return new CertAndKey(
                    key,
                    cert,
                    ("new-truststore" + index).getBytes(),
                    ("new-keystore" + index).getBytes(),
                    "new-password" + index);
        }

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