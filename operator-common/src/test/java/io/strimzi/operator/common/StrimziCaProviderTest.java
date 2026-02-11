/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common;

import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertManager;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.model.Ca;
import io.strimzi.operator.common.model.PasswordGenerator;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class StrimziCaProviderTest {
    private static final LinkedHashMap<String, Subject> SUBJECTS = new LinkedHashMap<>();
    // LinkedHashMap is used to maintain ordering and have predictable test results
    static {
        SUBJECTS.put("pod0", new Subject.Builder().build());
        SUBJECTS.put("pod1", new Subject.Builder().build());
        SUBJECTS.put("pod2", new Subject.Builder().build());
    }

    @Test
    public void renewalOfCertificatesWithNullCertificates() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(false);
        StrimziCaProvider mockedStrimziCaProvider = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedStrimziCaProvider.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                null,
                isMaintenanceTimeWindowsSatisfied
        );

        MatcherAssert.assertThat(new String(newCerts.get("pod0").cert()), CoreMatchers.is("new-cert0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").key()), CoreMatchers.is("new-key0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").keyStore()), CoreMatchers.is("new-keystore0"));
        MatcherAssert.assertThat(newCerts.get("pod0").storePassword(), CoreMatchers.is("new-password0"));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("new-cert1"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("new-key1"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").keyStore()), CoreMatchers.is("new-keystore1"));
        MatcherAssert.assertThat(newCerts.get("pod1").storePassword(), CoreMatchers.is("new-password1"));

        MatcherAssert.assertThat(new String(newCerts.get("pod2").cert()), CoreMatchers.is("new-cert2"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").key()), CoreMatchers.is("new-key2"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").keyStore()), CoreMatchers.is("new-keystore2"));
        MatcherAssert.assertThat(newCerts.get("pod2").storePassword(), CoreMatchers.is("new-password2"));
    }

    @Test
    public void renewalOfCertificatesWithCaRenewal() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(true);
        MockedStrimziCaProvider mockedCa = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied
        );

        MatcherAssert.assertThat(new String(newCerts.get("pod0").cert()), CoreMatchers.is("new-cert0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").key()), CoreMatchers.is("new-key0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").keyStore()), CoreMatchers.is("new-keystore0"));
        MatcherAssert.assertThat(newCerts.get("pod0").storePassword(), CoreMatchers.is("new-password0"));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("new-cert1"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("new-key1"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").keyStore()), CoreMatchers.is("new-keystore1"));
        MatcherAssert.assertThat(newCerts.get("pod1").storePassword(), CoreMatchers.is("new-password1"));

        MatcherAssert.assertThat(new String(newCerts.get("pod2").cert()), CoreMatchers.is("new-cert2"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").key()), CoreMatchers.is("new-key2"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").keyStore()), CoreMatchers.is("new-keystore2"));
        MatcherAssert.assertThat(newCerts.get("pod2").storePassword(), CoreMatchers.is("new-password2"));
    }

    @Test
    public void renewalOfCertificatesDelayedRenewalInWindow() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(false);
        MockedStrimziCaProvider mockedCa = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = true;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied
        );

        MatcherAssert.assertThat(new String(newCerts.get("pod0").cert()), CoreMatchers.is("new-cert0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").key()), CoreMatchers.is("new-key0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").keyStore()), CoreMatchers.is("new-keystore0"));
        MatcherAssert.assertThat(newCerts.get("pod0").storePassword(), CoreMatchers.is("new-password0"));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("new-cert1"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("new-key1"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").keyStore()), CoreMatchers.is("new-keystore1"));
        MatcherAssert.assertThat(newCerts.get("pod1").storePassword(), CoreMatchers.is("new-password1"));

        MatcherAssert.assertThat(new String(newCerts.get("pod2").cert()), CoreMatchers.is("new-cert2"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").key()), CoreMatchers.is("new-key2"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").keyStore()), CoreMatchers.is("new-keystore2"));
        MatcherAssert.assertThat(newCerts.get("pod2").storePassword(), CoreMatchers.is("new-password2"));
    }

    @Test
    public void renewalOfCertificatesDelayedRenewalOutsideWindow() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(false);
        MockedStrimziCaProvider mockedCa = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        
        boolean isMaintenanceTimeWindowsSatisfied = false;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied
        );

        MatcherAssert.assertThat(new String(newCerts.get("pod0").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").key()), CoreMatchers.is("old-key"));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("old-key"));

        MatcherAssert.assertThat(new String(newCerts.get("pod2").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").key()), CoreMatchers.is("old-key"));
    }

    @Test
    public void renewalOfCertificatesWithNewNodesOutsideWindow() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(false);
        MockedStrimziCaProvider mockedCa = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = false;

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied
        );

        MatcherAssert.assertThat(new String(newCerts.get("pod0").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").key()), CoreMatchers.is("old-key"));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("old-key"));

        MatcherAssert.assertThat(new String(newCerts.get("pod2").cert()), CoreMatchers.is("new-cert0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").key()), CoreMatchers.is("new-key0"));
    }

    @Test
    public void noRenewal() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(false);
        MockedStrimziCaProvider mockedCa = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                true
        );

        MatcherAssert.assertThat(new String(newCerts.get("pod0").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").key()), CoreMatchers.is("old-key"));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("old-key"));

        MatcherAssert.assertThat(new String(newCerts.get("pod2").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").key()), CoreMatchers.is("old-key"));
    }

    @Test
    public void noRenewalWithScaleUp() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(false);
        MockedStrimziCaProvider mockedCa = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                true
        );

        MatcherAssert.assertThat(new String(newCerts.get("pod0").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").key()), CoreMatchers.is("old-key"));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("new-cert0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("new-key0"));

        MatcherAssert.assertThat(new String(newCerts.get("pod2").cert()), CoreMatchers.is("new-cert1"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").key()), CoreMatchers.is("new-key1"));
    }

    @Test
    public void noRenewalWithScaleUpInTheMiddle() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(false);
        MockedStrimziCaProvider mockedCa = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                SUBJECTS,
                initialCerts,
                true
        );

        MatcherAssert.assertThat(new String(newCerts.get("pod0").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").key()), CoreMatchers.is("old-key"));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("new-cert0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("new-key0"));

        MatcherAssert.assertThat(new String(newCerts.get("pod2").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").key()), CoreMatchers.is("old-key"));
    }

    @Test
    public void noRenewalScaleDown() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(false);
        MockedStrimziCaProvider mockedCa = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                Map.of("pod1", new Subject.Builder().build()),
                initialCerts,
                true
        );

        MatcherAssert.assertThat(newCerts.get("pod0"), CoreMatchers.is(CoreMatchers.nullValue()));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("old-cert"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("old-key"));

        MatcherAssert.assertThat(newCerts.get("pod2"), CoreMatchers.is(CoreMatchers.nullValue()));
    }

    @Test
    public void changedSubject() throws IOException {
        Ca ca = Mockito.mock(Ca.class);
        Mockito.when(ca.certRenewed()).thenReturn(false);
        MockedStrimziCaProvider mockedCa = new MockedStrimziCaProvider(Reconciliation.DUMMY_RECONCILIATION, null, null, ca, 2, 1);
        mockedCa.setCertExpiring(true);

        Map<String, CertAndKey> initialCerts = new HashMap<>();
        initialCerts.put("pod0", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod1", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));
        initialCerts.put("pod2", new CertAndKey("old-key".getBytes(), "old-cert".getBytes()));

        boolean isMaintenanceTimeWindowsSatisfied = true;

        LinkedHashMap<String, Subject> updatedSubjects = new LinkedHashMap<>();
        updatedSubjects.put("pod0", new Subject.Builder().withCommonName("pod0").build());
        updatedSubjects.put("pod1", new Subject.Builder().withCommonName("pod1").build());
        updatedSubjects.put("pod2", new Subject.Builder().withCommonName("pod2").build());

        Map<String, CertAndKey> newCerts = mockedCa.maybeCopyOrGenerateCerts(
                Reconciliation.DUMMY_RECONCILIATION,
                updatedSubjects,
                initialCerts,
                isMaintenanceTimeWindowsSatisfied
        );

        MatcherAssert.assertThat(new String(newCerts.get("pod0").cert()), CoreMatchers.is("new-cert0"));
        MatcherAssert.assertThat(new String(newCerts.get("pod0").key()), CoreMatchers.is("new-key0"));

        MatcherAssert.assertThat(new String(newCerts.get("pod1").cert()), CoreMatchers.is("new-cert1"));
        MatcherAssert.assertThat(new String(newCerts.get("pod1").key()), CoreMatchers.is("new-key1"));

        MatcherAssert.assertThat(new String(newCerts.get("pod2").cert()), CoreMatchers.is("new-cert2"));
        MatcherAssert.assertThat(new String(newCerts.get("pod2").key()), CoreMatchers.is("new-key2"));
    }

    public static class MockedStrimziCaProvider extends StrimziCaProvider {
        private final AtomicInteger invocationCount = new AtomicInteger(0);
        private boolean isCertExpiring;

        public MockedStrimziCaProvider(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator, Ca ca, int validityDays, int renewalDays) {
            super(reconciliation, certManager, passwordGenerator, ca, validityDays, renewalDays);
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
                                                File csrFile, File keyFile, File certFile, File keyStoreFile) {
            int index = invocationCount.getAndIncrement();

            return new CertAndKey(
                    ("new-key" + index).getBytes(),
                    ("new-cert" + index).getBytes(),
                    ("new-truststore" + index).getBytes(),
                    ("new-keystore" + index).getBytes(),
                    "new-password" + index
            );
        }

        public void setCertExpiring(boolean certExpiring) {
            isCertExpiring = certExpiring;
        }
    }
}