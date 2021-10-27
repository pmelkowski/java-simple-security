package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;
import com.github.jss.providers.Provider;

public class EncoderTest {

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  DH,     2048",
        "BC,  DSA,    1024",
        "BC,  EC,      384",
        "BC,  RSA,    4096",
        "BC,  X25519,  255",
        "BC,  X448,    448",
        "BC,  XDH,     255",
        "BC,  XDH,     448",
        "SUN, DH,     2048",
        "SUN, DSA,    1024",
        "SUN, EC,      384",
        "SUN, RSA,    4096",
        "SUN, X25519,  255",
        "SUN, X448,    448",
        "SUN, XDH,     255",
        "SUN, XDH,     448"
    })
    public void testEncodeKey(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, int keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);

        String encodedPrivate = Encoder.encode(keyPair.getPrivate());
        String encodedPublic = Encoder.encode(keyPair.getPublic());

        PrivateKey decodedPrivate = provider.decodePrivateKey(algorithm, encodedPrivate);
        PublicKey decodedPublic = provider.decodePublicKey(algorithm, encodedPublic);

        assertAll(
            () -> assertTrue(provider.equals(keyPair.getPrivate(), decodedPrivate)),
            () -> assertTrue(provider.equals(keyPair.getPublic(), decodedPublic))
        );
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  DH,     2048",
        "BC,  DSA,    1024",
        "BC,  EC,      384",
        "BC,  RSA,    4096",
        "BC,  X25519,  255",
        "BC,  X448,    448",
        "BC,  XDH,     255",
        "BC,  XDH,     448"
    })
    public void testGetPEMKey(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, int keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);

        String pemPrivate = Encoder.getPEM(keyPair.getPrivate());
        String pemPublic = Encoder.getPEM(keyPair.getPublic());

        PrivateKey decodedPrivate = provider.decodePrivateKeyPEM(pemPrivate);
        PublicKey decodedPublic = provider.decodePublicKeyPEM(pemPublic);

        assertAll(
            () -> assertTrue(provider.equals(keyPair.getPrivate(), decodedPrivate)),
            () -> assertTrue(provider.equals(keyPair.getPublic(), decodedPublic))
        );
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  RSA, 4096, 0,  1, WEEKS,  000000000, MD5",
        "BC,  RSA, 1024, 2, 10, YEARS,  999999999, MD2",
        "BC,  DSA, 2048, 2,  3, DAYS,   232323232, SHA256",
        "BC,  DSA, 512,  0,  7, HOURS,  454545454, SHA1",
        "SUN, RSA, 1024, 0,  1, WEEKS,  000000000, MD5",
        "SUN, RSA, 1024, 2, 10, YEARS,  999999999, MD2",
        "SUN, RSA, 4096, 1,  2, MONTHS, 111111111, SHA384",
        "SUN, DSA, 2048, 2,  3, DAYS,   232323232, SHA256",
        "SUN, DSA, 512,  0,  7, HOURS,  454545454, SHA1"
    })
    public void testEncodeCertificate(@ConvertWith(ProviderConverter.class) Provider provider,
            String keyAlgorithm, int keySize, int version, int validityAmount, ChronoUnit validityUnit,
            BigInteger serialNumber, String signingAlgorithm) throws Exception {
        KeyPair keyPair = provider.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = provider.getX509Certificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        String encoded = Encoder.encode(certificate);
        Certificate decoded = provider.decodeCertificate("X.509", encoded);

        assertAll(
            () -> assertTrue(certificate.equals(decoded)),
            () -> assertTrue(keyPair.getPublic().equals(decoded.getPublicKey()))
        );
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  RSA, 4096, 0,  1, WEEKS,  000000000, MD5",
        "BC,  RSA, 1024, 2, 10, YEARS,  999999999, MD2",
        "BC,  DSA, 2048, 2,  3, DAYS,   232323232, SHA256",
        "BC,  DSA, 512,  0,  7, HOURS,  454545454, SHA1",
        "SUN, RSA, 1024, 0,  1, WEEKS,  000000000, MD5",
        "SUN, RSA, 1024, 2, 10, YEARS,  999999999, MD2",
        "SUN, RSA, 4096, 1,  2, MONTHS, 111111111, SHA384",
        "SUN, DSA, 2048, 2,  3, DAYS,   232323232, SHA256",
        "SUN, DSA, 512,  0,  7, HOURS,  454545454, SHA1"
    })
    public void testGetPEMCertificate(@ConvertWith(ProviderConverter.class) Provider provider,
            String keyAlgorithm, int keySize, int version, int validityAmount, ChronoUnit validityUnit,
            BigInteger serialNumber, String signingAlgorithm) throws Exception {
        KeyPair keyPair = provider.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = provider.getX509Certificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        String pem = Encoder.getPEM(certificate);
        Certificate decoded = provider.decodeCertificatePEM("X.509", pem);

        assertAll(
            () -> assertTrue(certificate.equals(decoded)),
            () -> assertTrue(keyPair.getPublic().equals(decoded.getPublicKey()))
        );
    }

}
