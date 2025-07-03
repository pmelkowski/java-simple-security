package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.time.temporal.ChronoUnit;

import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;
import com.github.jss.providers.Provider;

public class DecoderTest {

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPrivateKey",
        "BC,  EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  ML-DSA,         , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-44,      , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-65,      , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-87,      , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM,         , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-512,     , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-768,     , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-1024,    , sun.security.pkcs.NamedPKCS8Key",
        "BC,  RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPrivateKeyImpl",
        "SUN, DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "SUN, DSA,        1024, sun.security.provider.DSAPrivateKey",
        "SUN, EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "SUN, Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, ML-DSA,         , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-44,      , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-65,      , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-87,      , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM,         , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-512,     , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-768,     , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-1024,    , sun.security.pkcs.NamedPKCS8Key",
        "SUN, RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "SUN, RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "SUN, X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "SUN, X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "SUN, XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "SUN, XDH,         448, sun.security.ec.XDHPrivateKeyImpl"
    })
    public void testDecodePrivateKeyString(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        String encodedPrivate = provider.encodeKey(keyPair.getPrivate());

        PrivateKey decodedPrivate = Decoder.decodePrivateKey(encodedPrivate);

        assertEquals(keyClass, decodedPrivate.getClass());
        if ((keyPair.getPrivate() instanceof MLDSAPrivateKey)
                || (keyPair.getPrivate() instanceof MLKEMPrivateKey)) {
            // waiting for better equals()
        } else {
            assertEquals(keyPair.getPrivate(), decodedPrivate);
        }
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPrivateKey",
        "BC,  EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  ML-DSA,         , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-44,      , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-65,      , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-87,      , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM,         , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-512,     , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-768,     , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-1024,    , sun.security.pkcs.NamedPKCS8Key",
        "BC,  RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPrivateKeyImpl",
    })
    public void testDecodePrivateKeyPEM(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        String pemPrivate = provider.encodeToPEM(keyPair.getPrivate());

        PrivateKey decodedPrivate = Decoder.decodePrivateKey(pemPrivate);

        assertEquals(keyClass, decodedPrivate.getClass());
        if ((keyPair.getPrivate() instanceof MLDSAPrivateKey)
                || (keyPair.getPrivate() instanceof MLKEMPrivateKey)) {
            // waiting for better equals()
        } else {
            assertEquals(keyPair.getPrivate(), decodedPrivate);
        }
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPrivateKey",
        "BC,  EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  ML-DSA,         , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-44,      , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-65,      , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-87,      , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM,         , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-512,     , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-768,     , sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-1024,    , sun.security.pkcs.NamedPKCS8Key",
        "BC,  RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPrivateKeyImpl",
        "SUN, DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "SUN, DSA,        1024, sun.security.provider.DSAPrivateKey",
        "SUN, EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "SUN, Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, ML-DSA,         , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-44,      , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-65,      , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-87,      , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM,         , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-512,     , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-768,     , sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-1024,    , sun.security.pkcs.NamedPKCS8Key",
        "SUN, RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "SUN, RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "SUN, X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "SUN, X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "SUN, XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "SUN, XDH,         448, sun.security.ec.XDHPrivateKeyImpl"
    })
    public void testDecodePrivateKey(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        byte[] encodedPrivate = keyPair.getPrivate().getEncoded();

        PrivateKey decodedPrivate = Decoder.decodePrivateKey(encodedPrivate);

        assertEquals(keyClass, decodedPrivate.getClass());
        if ((keyPair.getPrivate() instanceof MLDSAPrivateKey)
                || (keyPair.getPrivate() instanceof MLKEMPrivateKey)) {
            // waiting for better equals()
        } else {
            assertEquals(keyPair.getPrivate(), decodedPrivate);
        }
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "BC,  EC,          384, sun.security.ec.ECPublicKeyImpl",
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  ML-DSA,         , sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-44,      , sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-65,      , sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-87,      , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM,         , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-512,     , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-768,     , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-1024,    , sun.security.x509.NamedX509Key",
        "BC,  RSA,        4096, sun.security.rsa.RSAPublicKeyImpl",
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPublicKeyImpl",
        "SUN, DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "SUN, DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "SUN, EC,          384, sun.security.ec.ECPublicKeyImpl",
        "SUN, Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, ML-DSA,         , sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-44,      , sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-65,      , sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-87,      , sun.security.x509.NamedX509Key",
        "SUN, ML-KEM,         , sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-512,     , sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-768,     , sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-1024,    , sun.security.x509.NamedX509Key",
        "SUN, RSA,        4096, sun.security.rsa.RSAPublicKeyImpl",
        "SUN, RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "SUN, X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "SUN, X448,           , sun.security.ec.XDHPublicKeyImpl",
        "SUN, XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "SUN, XDH,         448, sun.security.ec.XDHPublicKeyImpl"
    })
    public void testDecodePublicKeyString(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        String encodedPublic = provider.encodeKey(keyPair.getPublic());

        PublicKey decodedPublic = Decoder.decodePublicKey(encodedPublic);

        assertEquals(keyClass, decodedPublic.getClass());
        if ((keyPair.getPublic() instanceof MLDSAPublicKey)
                || (keyPair.getPublic() instanceof MLKEMPublicKey)) {
            // waiting for better equals()
        } else {
            assertEquals(keyPair.getPublic(), decodedPublic);
        }
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "BC,  EC,          384, sun.security.ec.ECPublicKeyImpl",
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  ML-DSA,         , sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-44,      , sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-65,      , sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-87,      , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM,         , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-512,     , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-768,     , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-1024,    , sun.security.x509.NamedX509Key",
        "BC,  RSA,        4096, sun.security.rsa.RSAPublicKeyImpl",
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPublicKeyImpl"
    })
    public void testDecodePublicKeyPEM(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        String pemPublic = provider.encodeToPEM(keyPair.getPublic());

        PublicKey decodedPublic = Decoder.decodePublicKey(pemPublic);

        assertEquals(keyClass, decodedPublic.getClass());
        if ((keyPair.getPublic() instanceof MLDSAPublicKey)
                || (keyPair.getPublic() instanceof MLKEMPublicKey)) {
            // waiting for better equals()
        } else {
            assertEquals(keyPair.getPublic(), decodedPublic);
        }
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "BC,  EC,          384, sun.security.ec.ECPublicKeyImpl",
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  ML-DSA,         , sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-44,      , sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-65,      , sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-87,      , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM,         , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-512,     , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-768,     , sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-1024,    , sun.security.x509.NamedX509Key",
        "BC,  RSA,        4096, sun.security.rsa.RSAPublicKeyImpl",
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPublicKeyImpl",
        "SUN, DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "SUN, DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "SUN, EC,          384, sun.security.ec.ECPublicKeyImpl",
        "SUN, Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, ML-DSA,         , sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-44,      , sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-65,      , sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-87,      , sun.security.x509.NamedX509Key",
        "SUN, ML-KEM,         , sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-512,     , sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-768,     , sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-1024,    , sun.security.x509.NamedX509Key",
        "SUN, RSA,        4096, sun.security.rsa.RSAPublicKeyImpl",
        "SUN, RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "SUN, X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "SUN, X448,           , sun.security.ec.XDHPublicKeyImpl",
        "SUN, XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "SUN, XDH,         448, sun.security.ec.XDHPublicKeyImpl"
    })
    public void testDecodePublicKey(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        KeyPair keyPair = provider.getKeyPair(algorithm, keySize);
        byte[] encodedPublic = keyPair.getPublic().getEncoded();

        PublicKey decodedPublic = Decoder.decodePublicKey(encodedPublic);

        assertEquals(keyClass, decodedPublic.getClass());
        if ((keyPair.getPublic() instanceof MLDSAPublicKey)
                || (keyPair.getPublic() instanceof MLKEMPublicKey)) {
            // waiting for better equals()
        } else {
            assertEquals(keyPair.getPublic(), decodedPublic);
        }
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  RSA, 4096, 0,  1, WEEKS,  000000000, MD5,     sun.security.x509.X509CertImpl",
        "BC,  RSA, 1024, 2, 10, YEARS,  999999999, MD2,     sun.security.x509.X509CertImpl",
        "BC,  DSA, 2048, 2,  3, DAYS,   232323232, SHA256,  sun.security.x509.X509CertImpl",
        "BC,  DSA, 512,  0,  7, HOURS,  454545454, SHA1,    sun.security.x509.X509CertImpl",
        "SUN, RSA, 1024, 0,  1, WEEKS,  000000000, MD5,     sun.security.x509.X509CertImpl",
        "SUN, RSA, 1024, 2, 10, YEARS,  999999999, MD2,     sun.security.x509.X509CertImpl",
        "SUN, RSA, 4096, 1,  2, MONTHS, 111111111, SHA384,  sun.security.x509.X509CertImpl",
        "SUN, DSA, 2048, 2,  3, DAYS,   232323232, SHA256,  sun.security.x509.X509CertImpl",
        "SUN, DSA, 512,  0,  7, HOURS,  454545454, SHA1,    sun.security.x509.X509CertImpl"
    })
    public void testDecodeCertificateString(@ConvertWith(ProviderConverter.class) Provider provider,
            String keyAlgorithm, int keySize, int version, int validityAmount, ChronoUnit validityUnit,
            BigInteger serialNumber, String signingAlgorithm, Class<?> certClass) throws Exception {
        KeyPair keyPair = provider.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = provider.getX509Certificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        String encoded = provider.encodeCertificate(certificate);
        Certificate decoded = Decoder.decodeCertificate(encoded);

        assertAll(
            () -> assertEquals(certificate, decoded),
            () -> assertEquals(certClass, decoded.getClass()),
            () -> assertEquals(keyPair.getPublic(), decoded.getPublicKey())
        );
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  RSA, 4096, 0,  1, WEEKS,  000000000, MD5,     sun.security.x509.X509CertImpl",
        "BC,  RSA, 1024, 2, 10, YEARS,  999999999, MD2,     sun.security.x509.X509CertImpl",
        "BC,  DSA, 2048, 2,  3, DAYS,   232323232, SHA256,  sun.security.x509.X509CertImpl",
        "BC,  DSA, 512,  0,  7, HOURS,  454545454, SHA1,    sun.security.x509.X509CertImpl"
    })
    public void testDecodeCertificatePEM(@ConvertWith(ProviderConverter.class) Provider provider,
            String keyAlgorithm, int keySize, int version, int validityAmount, ChronoUnit validityUnit,
            BigInteger serialNumber, String signingAlgorithm, Class<?> certClass) throws Exception {
        KeyPair keyPair = provider.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = provider.getX509Certificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        String pem = provider.encodeToPEM(certificate);
        Certificate decoded = Decoder.decodeCertificate(pem);

        assertAll(
            () -> assertEquals(certificate, decoded),
            () -> assertEquals(certClass, decoded.getClass()),
            () -> assertEquals(keyPair.getPublic(), decoded.getPublicKey())
        );
    }

    @SuppressWarnings("exports")
    @ParameterizedTest
    @CsvSource({
        "BC,  RSA, 4096, 0,  1, WEEKS,  000000000, MD5,     sun.security.x509.X509CertImpl",
        "BC,  RSA, 1024, 2, 10, YEARS,  999999999, MD2,     sun.security.x509.X509CertImpl",
        "BC,  DSA, 2048, 2,  3, DAYS,   232323232, SHA256,  sun.security.x509.X509CertImpl",
        "BC,  DSA, 512,  0,  7, HOURS,  454545454, SHA1,    sun.security.x509.X509CertImpl",
        "SUN, RSA, 1024, 0,  1, WEEKS,  000000000, MD5,     sun.security.x509.X509CertImpl",
        "SUN, RSA, 1024, 2, 10, YEARS,  999999999, MD2,     sun.security.x509.X509CertImpl",
        "SUN, RSA, 4096, 1,  2, MONTHS, 111111111, SHA384,  sun.security.x509.X509CertImpl",
        "SUN, DSA, 2048, 2,  3, DAYS,   232323232, SHA256,  sun.security.x509.X509CertImpl",
        "SUN, DSA, 512,  0,  7, HOURS,  454545454, SHA1,    sun.security.x509.X509CertImpl"
    })
    public void testDecodeCertificate(@ConvertWith(ProviderConverter.class) Provider provider,
            String keyAlgorithm, int keySize, int version, int validityAmount, ChronoUnit validityUnit,
            BigInteger serialNumber, String signingAlgorithm, Class<?> certClass) throws Exception {
        KeyPair keyPair = provider.getKeyPair(keyAlgorithm, keySize);
        signingAlgorithm = signingAlgorithm + "with" + keyAlgorithm;
        Certificate certificate = provider.getX509Certificate(
                keyPair.getPublic(), keyPair.getPrivate(),
                version, validityAmount, validityUnit, serialNumber, signingAlgorithm);

        byte[] encoded = certificate.getEncoded();
        Certificate decoded = Decoder.decodeCertificate(encoded);

        assertAll(
            () -> assertEquals(certificate, decoded),
            () -> assertEquals(certClass, decoded.getClass()),
            () -> assertEquals(keyPair.getPublic(), decoded.getPublicKey())
        );
    }

}
