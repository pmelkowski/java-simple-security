package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class EncoderTest {

    @ParameterizedTest
    @CsvSource({
        "DH,   512",
        "DSA, 1024",
        "EC,   384",
        "RSA, 4096"
    })
    public void testEncodeKeys(String algorithm, int keySize) throws Exception {
        KeyPair keyPair = TestUtils.getKeyPair(algorithm, keySize);

        String encodedPrivate = Encoder.encode(keyPair.getPrivate());
        String encodedPublic = Encoder.encode(keyPair.getPublic());

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PrivateKey decodedPrivate = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedPrivate)));
        PublicKey decodedPublic = keyFactory.generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(encodedPublic)));

        assertAll(
            () -> assertTrue(keyPair.getPrivate().equals(decodedPrivate)),
            () -> assertTrue(keyPair.getPublic().equals(decodedPublic))
        );
    }

    @ParameterizedTest
    @CsvSource({
        "RSA, 1024, 0,  1, WEEKS,  000000000, MD5",
        "RSA, 1024, 2, 10, YEARS,  999999999, MD2",
        "RSA, 4096, 1,  2, MONTHS, 111111111, SHA384",
        "DSA, 2048, 2,  3, DAYS,   232323232, SHA256",
        "DSA, 512,  0,  7, HOURS,  454545454, SHA1",
    })
    public void testEncodeCertificate(String keyAlgorithm, int keySize,
            int version, int validityAmount, ChronoUnit validityUnit, BigInteger serialNumber,
            String signingAlgorithm) throws Exception {
        KeyPair keyPair = TestUtils.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = TestUtils.getCertificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        String encoded = Encoder.encode(certificate);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate decoded = certFactory.generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(encoded.getBytes())));

        assertAll(
            () -> assertTrue(certificate.equals(decoded)),
            () -> assertTrue(keyPair.getPublic().equals(decoded.getPublicKey()))
        );
    }

}
