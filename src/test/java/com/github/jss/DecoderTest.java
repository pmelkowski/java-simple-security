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

public class DecoderTest {

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
    public void testDecodePrivateKeyString(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, int keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        String encodedPrivate = provider.encodeKey(keyPair.getPrivate());

        PrivateKey decodedPrivate = Decoder.decodePrivateKey(encodedPrivate);
        assertTrue(provider.equals(keyPair.getPrivate(), decodedPrivate));
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
    public void testDecoderivateKeyPEM(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, int keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        String pemPrivate = provider.encodeToPEM(keyPair.getPrivate());

        PrivateKey decodedPrivate = Decoder.decodePrivateKey(pemPrivate);
        assertTrue(provider.equals(keyPair.getPrivate(), decodedPrivate));
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
    public void testDecodePrivateKey(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, int keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        byte[] encodedPrivate = keyPair.getPrivate().getEncoded();

        PrivateKey decodedPrivate = Decoder.decodePrivateKey(encodedPrivate);
        assertTrue(provider.equals(keyPair.getPrivate(), decodedPrivate));
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
    public void testDecodePublicKeyString(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, int keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        String encodedPublic = provider.encodeKey(keyPair.getPublic());

        PublicKey decodedPublic = Decoder.decodePublicKey(encodedPublic);
        assertTrue(provider.equals(keyPair.getPublic(), decodedPublic));
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
    public void testDecodePublicKeyPEM(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, int keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        String pemPublic = provider.encodeToPEM(keyPair.getPublic());

        PublicKey decodedPublic = Decoder.decodePublicKey(pemPublic);
        assertTrue(provider.equals(keyPair.getPublic(), decodedPublic));
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
    public void testDecodePublicKey(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, int keySize) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        byte[] encodedPublic = keyPair.getPublic().getEncoded();

        PublicKey decodedPublic = Decoder.decodePublicKey(encodedPublic);
        assertTrue(provider.equals(keyPair.getPublic(), decodedPublic));
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
    public void testDecodeCertificateString(@ConvertWith(ProviderConverter.class) Provider provider,
            String keyAlgorithm, int keySize, int version, int validityAmount, ChronoUnit validityUnit,
            BigInteger serialNumber, String signingAlgorithm) throws Exception {
        KeyPair keyPair = provider.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = provider.getX509Certificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        String encoded = provider.encodeCertificate(certificate);
        Certificate decoded = Decoder.decodeCertificate(encoded);

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
        "BC,  DSA, 512,  0,  7, HOURS,  454545454, SHA1"
    })
    public void testDecodeCertificatePEM(@ConvertWith(ProviderConverter.class) Provider provider,
            String keyAlgorithm, int keySize, int version, int validityAmount, ChronoUnit validityUnit,
            BigInteger serialNumber, String signingAlgorithm) throws Exception {
        KeyPair keyPair = provider.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = provider.getX509Certificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        String pem = provider.encodeToPEM(certificate);
        Certificate decoded = Decoder.decodeCertificate(pem);

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
    public void testDecodeCertificate(@ConvertWith(ProviderConverter.class) Provider provider,
            String keyAlgorithm, int keySize, int version, int validityAmount, ChronoUnit validityUnit,
            BigInteger serialNumber, String signingAlgorithm) throws Exception {
        KeyPair keyPair = provider.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = provider.getX509Certificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        byte[] encoded = certificate.getEncoded();
        Certificate decoded = Decoder.decodeCertificate(encoded);

        assertAll(
            () -> assertTrue(certificate.equals(decoded)),
            () -> assertTrue(keyPair.getPublic().equals(decoded.getPublicKey()))
        );
    }

}
