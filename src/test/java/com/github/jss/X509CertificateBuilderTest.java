package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import sun.security.x509.CertificateVersion;

public class X509CertificateBuilderTest {
    protected static final X500Principal SUBJECT =
            new X500Principal("O=GitHub, OU=SimpleJavaSecurity, CN=subject");
    protected static final X500Principal ISSUER =
            new X500Principal("O=GitHub, OU=SimpleJavaSecurity, CN=issuer");
    protected static final KeyPair SUBJECT_KEYS;
    protected static final KeyPair ISSUER_KEYS;
    static {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Defaults.getKeyAlgorithm());
            keyGen.initialize(Defaults.getKeySize());
            SUBJECT_KEYS = keyGen.generateKeyPair();
            ISSUER_KEYS = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        }
    }

    @Test
    public void testDefault() throws Exception {
        X509Certificate certificate = X509CertificateBuilder.defaultCertificate(
                SUBJECT.getName(), ISSUER.getName(), SUBJECT_KEYS.getPublic(), ISSUER_KEYS.getPrivate());
        assertAll(
            () -> assertEquals(Defaults.getCertificateVersion(), certificate.getVersion() - 1),
            () -> assertEquals(SUBJECT, certificate.getSubjectX500Principal()),
            () -> assertEquals(ISSUER, certificate.getIssuerX500Principal()),
            () -> assertEquals(SUBJECT_KEYS.getPublic(), certificate.getPublicKey()),
            () -> assertEquals(Defaults.getSigningAlgorithm(), certificate.getSigAlgName()),
            () -> assertNotNull(certificate.getNotBefore()),
            () -> assertNotNull(certificate.getNotAfter()),
            () -> assertNotNull(certificate.getSerialNumber()),
            () -> assertDoesNotThrow(() -> certificate.checkValidity())
        );
    }

    @Test
    public void testDefaultSelfSigned() throws Exception {
        X509Certificate certificate = X509CertificateBuilder.defaultSelfSignedCertificate(
                SUBJECT.getName(), SUBJECT_KEYS);
        assertAll(
            () -> assertEquals(Defaults.getCertificateVersion(), certificate.getVersion() - 1),
            () -> assertEquals(SUBJECT, certificate.getSubjectX500Principal()),
            () -> assertEquals(SUBJECT, certificate.getIssuerX500Principal()),
            () -> assertEquals(SUBJECT_KEYS.getPublic(), certificate.getPublicKey()),
            () -> assertEquals(Defaults.getSigningAlgorithm(), certificate.getSigAlgName()),
            () -> assertNotNull(certificate.getNotBefore()),
            () -> assertNotNull(certificate.getNotAfter()),
            () -> assertNotNull(certificate.getSerialNumber()),
            () -> assertDoesNotThrow(() -> certificate.checkValidity())
        );
    }

    @Test
    public void testValid() throws Exception {
        X509CertificateBuilder builder = new X509CertificateBuilder(
                SUBJECT.getName(), ISSUER.getName(), SUBJECT_KEYS.getPublic(), ISSUER_KEYS.getPrivate())
            .withValidityFromNow(1, ChronoUnit.WEEKS)
            .withSerialNumber(BigInteger.TWO)
            .withVersion(CertificateVersion.V2)
            .withSigningAlgorithm("MD5withRSA");
        X509Certificate certificate = builder.build();
        assertAll(
            () -> commonChecks(builder, certificate),
            () -> assertDoesNotThrow(() -> certificate.checkValidity())
        );
    }

    @Test
    public void testExpired() throws Exception {
        X509CertificateBuilder builder = new X509CertificateBuilder(
                SUBJECT.getName(), ISSUER.getName(), SUBJECT_KEYS.getPublic(), ISSUER_KEYS.getPrivate())
            .withNotAfter(new Date());
        X509Certificate certificate = builder.build();
        assertAll(
            () -> commonChecks(builder, certificate),
            () -> assertThrows(CertificateExpiredException.class, () -> certificate.checkValidity())
        );
    }

    @Test
    public void testNotYetValid() throws Exception {
        X509CertificateBuilder builder = new X509CertificateBuilder(
                SUBJECT.getName(), ISSUER.getName(), SUBJECT_KEYS.getPublic(), ISSUER_KEYS.getPrivate())
            .withNotBefore(Date.from(ZonedDateTime.now().plus(1, ChronoUnit.WEEKS).toInstant()));
        X509Certificate certificate = builder.build();
        assertAll(
            () -> commonChecks(builder, certificate),
            () -> assertThrows(CertificateNotYetValidException.class, () -> certificate.checkValidity())
        );
    }

    protected static void commonChecks(X509CertificateBuilder builder, X509Certificate certificate) {
        assertAll(
            () -> assertEquals(builder.version, certificate.getVersion() - 1),
            () -> assertEquals(builder.subject.asX500Principal(), certificate.getSubjectX500Principal()),
            () -> assertEquals(builder.issuer.asX500Principal(), certificate.getIssuerX500Principal()),
            () -> assertEquals(builder.subjectKey, certificate.getPublicKey()),
            () -> assertEquals(builder.signingAlgorithm, certificate.getSigAlgName()),
            () -> assertEquals(builder.notBefore, certificate.getNotBefore()),
            () -> assertEquals(builder.notAfter, certificate.getNotAfter()),
            () -> {
                if (builder.serialNumber != null) {
                    assertEquals(builder.serialNumber, certificate.getSerialNumber());
                } else {
                    assertNotNull(certificate.getSerialNumber());
                }
            }
        );
    }

}
