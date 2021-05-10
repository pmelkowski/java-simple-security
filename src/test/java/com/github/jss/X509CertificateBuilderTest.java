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
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
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

    @ParameterizedTest
    @CsvSource({
        "0,  1, WEEKS,  000000000, MD5withRSA",
        "1,  2, MONTHS, 111111111, SHA384withRSA",
        "2, 10, YEARS,  999999999, MD2withRSA",
    })
    public void testValid(int version, int validityAmount, ChronoUnit validityUnit, BigInteger serialNumber,
            String signingAlgorithm) throws Exception {
        X509CertificateBuilder builder = new X509CertificateBuilder(
                SUBJECT.getName(), ISSUER.getName(), SUBJECT_KEYS.getPublic(), ISSUER_KEYS.getPrivate())
            .withVersion(version)
            .withValidity(validityAmount, validityUnit)
            .withSerialNumber(serialNumber)
            .withSigningAlgorithm(signingAlgorithm);
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
            .withNotBefore(new Date())
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
            .withNotBefore(LocalDate.now().plus(1, ChronoUnit.WEEKS));
        X509Certificate certificate = builder.build();
        assertAll(
            () -> commonChecks(builder, certificate),
            () -> assertThrows(CertificateNotYetValidException.class, () -> certificate.checkValidity())
        );
    }

    protected static void commonChecks(X509CertificateBuilder builder, X509Certificate certificate) {
        assertAll(
            () -> assertEquals(builder.version.get(CertificateVersion.VERSION), certificate.getVersion() - 1),
            () -> assertEquals(builder.subject.asX500Principal(), certificate.getSubjectX500Principal()),
            () -> assertEquals(builder.issuer.asX500Principal(), certificate.getIssuerX500Principal()),
            () -> assertEquals(builder.subjectKey, certificate.getPublicKey()),
            () -> assertEquals(builder.signingAlgorithm.getName(), certificate.getSigAlgName()),
            () -> assertEquals(Date.from(builder.notBefore), certificate.getNotBefore()),
            () -> assertEquals(Date.from(builder.notAfter), certificate.getNotAfter()),
            () -> assertEquals(builder.serialNumber, certificate.getSerialNumber())
        );
    }

}
