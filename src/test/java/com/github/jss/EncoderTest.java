package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
        "BC,  EdDSA,   255",
        "BC,  EdDSA,   448",
        "BC,  ML-DSA,     ",
        "BC,  ML-KEM,     ",
        "BC,  RSA,    4096",
        "BC,  X25519,  255",
        "BC,  X448,    448",
        "BC,  XDH,     255",
        "BC,  XDH,     448",
        "SUN, DH,     2048",
        "SUN, DSA,    1024",
        "SUN, EC,      384",
        "SUN, EdDSA,   255",
        "SUN, EdDSA,   448",
        "SUN, ML-DSA,     ",
        "SUN, ML-KEM,     ",
        "SUN, RSA,    4096",
        "SUN, X25519,  255",
        "SUN, X448,    448",
        "SUN, XDH,     255",
        "SUN, XDH,     448"
    })
    public void testEncodeKey(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);

        String encodedPrivate = Encoder.encode(keyPair.getPrivate());
        String encodedPublic = Encoder.encode(keyPair.getPublic());

        PrivateKey decodedPrivate = provider.decodePrivateKey(algorithm, encodedPrivate);
        PublicKey decodedPublic = provider.decodePublicKey(algorithm, encodedPublic);

        assertAll(
            () -> assertEquals(keyPair.getPrivate(), decodedPrivate),
            () -> assertEquals(keyPair.getPublic(), decodedPublic)
        );
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  DH,     2048",
        "BC,  DSA,    1024",
        "BC,  EC,      384",
        "BC,  EdDSA,   255",
        "BC,  EdDSA,   448",
        "BC,  ML-DSA,     ",
        "BC,  ML-KEM,     ",
        "BC,  RSA,    4096",
        "BC,  X25519,  255",
        "BC,  X448,    448",
        "BC,  XDH,     255",
        "BC,  XDH,     448"
    })
    public void testEncodeKeyToPEM(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);

        String pemPrivate = Encoder.encodeToPEM(keyPair.getPrivate());
        String pemPublic = Encoder.encodeToPEM(keyPair.getPublic());

        PrivateKey decodedPrivate = provider.decodePrivateKeyPEM(pemPrivate);
        PublicKey decodedPublic = provider.decodePublicKeyPEM(pemPublic);

        assertAll(
            () -> assertEquals(keyPair.getPrivate(), decodedPrivate),
            () -> assertEquals(keyPair.getPublic(), decodedPublic)
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
            () -> assertEquals(certificate, decoded),
            () -> assertEquals(keyPair.getPublic(), decoded.getPublicKey())
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
    public void testEncodeCertificateToPEM(@ConvertWith(ProviderConverter.class) Provider provider,
            String keyAlgorithm, int keySize, int version, int validityAmount, ChronoUnit validityUnit,
            BigInteger serialNumber, String signingAlgorithm) throws Exception {
        KeyPair keyPair = provider.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = provider.getX509Certificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        String pem = Encoder.encodeToPEM(certificate);
        Certificate decoded = provider.decodeCertificatePEM("X.509", pem);

        assertAll(
            () -> assertEquals(certificate, decoded),
            () -> assertEquals(keyPair.getPublic(), decoded.getPublicKey())
        );
    }

}
