package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;

import com.github.jss.providers.Provider;

@SuppressWarnings("exports")
public class DecoderTest {

    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPrivateKey",
        "BC,  EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "BC,  RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "SUN, DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "SUN, DSA,        1024, sun.security.provider.DSAPrivateKey",
        "SUN, EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "SUN, RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl"
    })
    public void testDecodePrivateKeyStringJdk9(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePrivateKeyString(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 11)
    @ParameterizedTest
    @CsvSource({
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPrivateKeyImpl",
        "SUN, RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "SUN, X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "SUN, X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "SUN, XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "SUN, XDH,         448, sun.security.ec.XDHPrivateKeyImpl"
    })
    public void testDecodePrivateKeyStringJdk11(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePrivateKeyString(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 15)
    @ParameterizedTest
    @CsvSource({
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl"
    })
    public void testDecodePrivateKeyStringJdk15(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePrivateKeyString(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 24)
    @ParameterizedTest
    @CsvSource({
        "BC,  ML-DSA,       sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-44,    sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-65,    sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-87,    sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM,       sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-512,   sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-768,   sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-1024,  sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA,       sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-44,    sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-65,    sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-87,    sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM,       sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-512,   sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-768,   sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-1024,  sun.security.pkcs.NamedPKCS8Key"
    })
    public void testDecodeNamedPrivateKeyString(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Class<?> keyClass) throws Exception {
        testDecodePrivateKeyString(provider, algorithm, null, keyClass);
    }

    private static void testDecodePrivateKeyString(Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        PrivateKey privateKey = provider.getKeyPair(algorithm, keySize).getPrivate();
        String encodedPrivate = provider.encodeKey(privateKey);

        PrivateKey decodedPrivate = Decoder.decodePrivateKey(encodedPrivate);

        assertAll(
            () -> assertEquals(keyClass, decodedPrivate.getClass()),
            () -> assertKeyEquals(privateKey, decodedPrivate)
        );
    }


    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPrivateKey",
        "BC,  EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "BC,  RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl"
    })
    public void testDecodePrivateKeyPemJdk9(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePrivateKeyPem(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 11)
    @ParameterizedTest
    @CsvSource({
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPrivateKeyImpl"
    })
    public void testDecodePrivateKeyPemJdk11(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePrivateKeyPem(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 15)
    @ParameterizedTest
    @CsvSource({
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl"

    })
    public void testDecodePrivateKeyPemJdk15(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePrivateKeyPem(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 24)
    @ParameterizedTest
    @CsvSource({
        "BC,  ML-DSA,       sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-44,    sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-65,    sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-87,    sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM,       sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-512,   sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-768,   sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-1024,  sun.security.pkcs.NamedPKCS8Key"
    })
    public void testDecodeNamedPrivateKeyPem(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Class<?> keyClass) throws Exception {
        testDecodePrivateKeyPem(provider, algorithm, null, keyClass);
    }

    private static void testDecodePrivateKeyPem(Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        PrivateKey privateKey = provider.getKeyPair(algorithm, keySize).getPrivate();
        String pemPrivate = provider.encodeToPEM(privateKey);

        PrivateKey decodedPrivate = Decoder.decodePrivateKey(pemPrivate);

        assertAll(
            () -> assertEquals(keyClass, decodedPrivate.getClass()),
            () -> assertKeyEquals(privateKey, decodedPrivate)
        );
    }


    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPrivateKey",
        "BC,  EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "BC,  RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "SUN, DH,         2048, com.sun.crypto.provider.DHPrivateKey",
        "SUN, DSA,        1024, sun.security.provider.DSAPrivateKey",
        "SUN, EC,          384, sun.security.ec.ECPrivateKeyImpl",
        "SUN, RSA,        4096, sun.security.rsa.RSAPrivateCrtKeyImpl"
    })
    public void testDecodePrivateKeyJdk9(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePrivateKey(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 11)
    @ParameterizedTest
    @CsvSource({
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPrivateKeyImpl",
        "SUN, RSASSA-PSS, 3072, sun.security.rsa.RSAPrivateCrtKeyImpl",
        "SUN, X25519,         , sun.security.ec.XDHPrivateKeyImpl",
        "SUN, X448,           , sun.security.ec.XDHPrivateKeyImpl",
        "SUN, XDH,         255, sun.security.ec.XDHPrivateKeyImpl",
        "SUN, XDH,         448, sun.security.ec.XDHPrivateKeyImpl"
    })
    public void testDecodePrivateKeyJdk11(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePrivateKey(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 15)
    @ParameterizedTest
    @CsvSource({
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, Ed25519,        , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, Ed448,          , sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, EdDSA,       255, sun.security.ec.ed.EdDSAPrivateKeyImpl",
        "SUN, EdDSA,       448, sun.security.ec.ed.EdDSAPrivateKeyImpl"
    })
    public void testDecodePrivateKeyJdk15(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePrivateKey(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 24)
    @ParameterizedTest
    @CsvSource({
        "BC,  ML-DSA,       sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-44,    sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-65,    sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-DSA-87,    sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM,       sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-512,   sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-768,   sun.security.pkcs.NamedPKCS8Key",
        "BC,  ML-KEM-1024,  sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA,       sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-44,    sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-65,    sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-DSA-87,    sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM,       sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-512,   sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-768,   sun.security.pkcs.NamedPKCS8Key",
        "SUN, ML-KEM-1024,  sun.security.pkcs.NamedPKCS8Key"
    })
    public void testDecodeNamedPrivateKey(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Class<?> keyClass) throws Exception {
        testDecodePrivateKey(provider, algorithm, null, keyClass);
    }

    private static void testDecodePrivateKey(Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        PrivateKey privateKey = provider.getKeyPair(algorithm, keySize).getPrivate();
        byte[] encodedPrivate = privateKey.getEncoded();

        PrivateKey decodedPrivate = Decoder.decodePrivateKey(encodedPrivate);

        assertAll(
            () -> assertEquals(keyClass, decodedPrivate.getClass()),
            () -> assertKeyEquals(privateKey, decodedPrivate)
        );
    }


    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "BC,  EC,          384, sun.security.ec.ECPublicKeyImpl",
        "BC,  RSA,        4096, sun.security.rsa.RSAPublicKeyImpl",
        "SUN, DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "SUN, DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "SUN, EC,          384, sun.security.ec.ECPublicKeyImpl",
        "SUN, RSA,        4096, sun.security.rsa.RSAPublicKeyImpl"
    })
    public void testDecodePublicKeyStringJdk9(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePublicKeyString(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 11)
    @ParameterizedTest
    @CsvSource({
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPublicKeyImpl",
        "SUN, RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "SUN, X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "SUN, X448,           , sun.security.ec.XDHPublicKeyImpl",
        "SUN, XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "SUN, XDH,         448, sun.security.ec.XDHPublicKeyImpl"
    })
    public void testDecodePublicKeyStringJdk11(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePublicKeyString(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 15)
    @ParameterizedTest
    @CsvSource({
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl"
    })
    public void testDecodePublicKeyStringJdk15(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePublicKeyString(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 24)
    @ParameterizedTest
    @CsvSource({
        "BC,  ML-DSA,       sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-44,    sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-65,    sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-87,    sun.security.x509.NamedX509Key",
        "BC,  ML-KEM,       sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-512,   sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-768,   sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-1024,  sun.security.x509.NamedX509Key",
        "SUN, ML-DSA,       sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-44,    sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-65,    sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-87,    sun.security.x509.NamedX509Key",
        "SUN, ML-KEM,       sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-512,   sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-768,   sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-1024,  sun.security.x509.NamedX509Key"
    })
    public void testDecodeNamedPublicKeyString(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Class<?> keyClass) throws Exception {
        testDecodePublicKeyString(provider, algorithm, null, keyClass);
    }

    private static void testDecodePublicKeyString(Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        PublicKey publicKey = provider.getKeyPair(algorithm, keySize).getPublic();
        String encodedPublic = provider.encodeKey(publicKey);

        PublicKey decodedPublic = Decoder.decodePublicKey(encodedPublic);

        assertAll(
            () -> assertEquals(keyClass, decodedPublic.getClass()),
            () -> assertKeyEquals(publicKey, decodedPublic)
        );
    }


    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "BC,  EC,          384, sun.security.ec.ECPublicKeyImpl",
        "BC,  RSA,        4096, sun.security.rsa.RSAPublicKeyImpl"
    })
    public void testDecodePublicKeyPemJdk9(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePublicKeyPem(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 11)
    @ParameterizedTest
    @CsvSource({
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPublicKeyImpl"
    })
    public void testDecodePublicKeyPemJdk11(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePublicKeyPem(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 15)
    @ParameterizedTest
    @CsvSource({
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl"
    })
    public void testDecodePublicKeyPemJdk15(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePublicKeyPem(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 24)
    @ParameterizedTest
    @CsvSource({
        "BC,  ML-DSA,       sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-44,    sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-65,    sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-87,    sun.security.x509.NamedX509Key",
        "BC,  ML-KEM,       sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-512,   sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-768,   sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-1024,  sun.security.x509.NamedX509Key"
    })
    public void testDecodeNamedPublicKeyPEM(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Class<?> keyClass) throws Exception {
        testDecodePublicKeyPem(provider, algorithm, null, keyClass);
    }

    private static void testDecodePublicKeyPem(Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        PublicKey publicKey = provider.getKeyPair(algorithm, keySize).getPublic();
        String pemPublic = provider.encodeToPEM(publicKey);

        PublicKey decodedPublic = Decoder.decodePublicKey(pemPublic);

        assertAll(
            () -> assertEquals(keyClass, decodedPublic.getClass()),
            () -> assertKeyEquals(publicKey, decodedPublic)
        );
    }


    @ParameterizedTest
    @CsvSource({
        "BC,  DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "BC,  DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "BC,  EC,          384, sun.security.ec.ECPublicKeyImpl",
        "BC,  RSA,        4096, sun.security.rsa.RSAPublicKeyImpl",
        "SUN, DH,         2048, com.sun.crypto.provider.DHPublicKey",
        "SUN, DSA,        1024, sun.security.provider.DSAPublicKeyImpl",
        "SUN, EC,          384, sun.security.ec.ECPublicKeyImpl",
        "SUN, RSA,        4096, sun.security.rsa.RSAPublicKeyImpl"
    })
    public void testDecodePublicKeyJdk9(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePublicKey(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 11)
    @ParameterizedTest
    @CsvSource({
        "BC,  RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "BC,  X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "BC,  X448,           , sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "BC,  XDH,         448, sun.security.ec.XDHPublicKeyImpl",
        "SUN, RSASSA-PSS, 3072, sun.security.rsa.RSAPublicKeyImpl",
        "SUN, X25519,         , sun.security.ec.XDHPublicKeyImpl",
        "SUN, X448,           , sun.security.ec.XDHPublicKeyImpl",
        "SUN, XDH,         255, sun.security.ec.XDHPublicKeyImpl",
        "SUN, XDH,         448, sun.security.ec.XDHPublicKeyImpl"
    })
    public void testDecodePublicKeyJdk11(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePublicKey(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 15)
    @ParameterizedTest
    @CsvSource({
        "BC,  Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "BC,  EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, Ed25519,        , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, Ed448,          , sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, EdDSA,       255, sun.security.ec.ed.EdDSAPublicKeyImpl",
        "SUN, EdDSA,       448, sun.security.ec.ed.EdDSAPublicKeyImpl"
    })
    public void testDecodePublicKeyJdk15(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        testDecodePublicKey(provider, algorithm, keySize, keyClass);
    }

    @EnabledForJreRange(minVersion = 24)
    @ParameterizedTest
    @CsvSource({
        "BC,  ML-DSA,       sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-44,    sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-65,    sun.security.x509.NamedX509Key",
        "BC,  ML-DSA-87,    sun.security.x509.NamedX509Key",
        "BC,  ML-KEM,       sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-512,   sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-768,   sun.security.x509.NamedX509Key",
        "BC,  ML-KEM-1024,  sun.security.x509.NamedX509Key",
        "SUN, ML-DSA,       sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-44,    sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-65,    sun.security.x509.NamedX509Key",
        "SUN, ML-DSA-87,    sun.security.x509.NamedX509Key",
        "SUN, ML-KEM,       sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-512,   sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-768,   sun.security.x509.NamedX509Key",
        "SUN, ML-KEM-1024,  sun.security.x509.NamedX509Key"
    })
    public void testDecodeNamedPublicKey(@ConvertWith(ProviderConverter.class) Provider provider,
            String algorithm, Class<?> keyClass) throws Exception {
        testDecodePublicKey(provider, algorithm, null, keyClass);
    }

    private static void testDecodePublicKey(Provider provider,
            String algorithm, Integer keySize, Class<?> keyClass) throws Exception {
        PublicKey publicKey = provider.getKeyPair(algorithm, keySize).getPublic();
        byte[] encodedPublic = publicKey.getEncoded();

        PublicKey decodedPublic = Decoder.decodePublicKey(encodedPublic);

        assertAll(
            () -> assertEquals(keyClass, decodedPublic.getClass()),
            () -> assertKeyEquals(publicKey, decodedPublic)
        );
    }


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
            () -> assertKeyEquals(keyPair.getPublic(), decoded.getPublicKey())
        );
    }

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
            () -> assertKeyEquals(keyPair.getPublic(), decoded.getPublicKey())
        );
    }

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
            () -> assertKeyEquals(keyPair.getPublic(), decoded.getPublicKey())
        );
    }


    private static byte[] INVALID_X25519 = new byte[] {48, 7, 6, 3, 43, 101, 110, 5, 0};
    private static byte[] INVALID_X448 =   new byte[] {48, 7, 6, 3, 43, 101, 111, 5, 0};

    private static void assertKeyEquals(Key expected, Key actual) {
        byte[] encodedExpected = expected.getEncoded();
        byte[] encodedActual = actual.getEncoded();

        switch (actual.getAlgorithm()) {
        case "ML-DSA":
        case "ML-KEM":
            if (actual.getFormat().equals("PKCS#8")) {
                int offset = actual.getAlgorithm().equals("ML-DSA") ? 38 : 70;
                if (encodedExpected.length - encodedActual.length == offset) {
                    // ignore seed in private key - supported since JDK 26
                    // https://bugs.openjdk.org/browse/JDK-8347941
                    byte[] keyExpected = Arrays.copyOfRange(encodedExpected, 24 + offset, encodedExpected.length);
                    byte[] keyActual = Arrays.copyOfRange(encodedActual, 24, encodedActual.length);
                    assertArrayEquals(keyExpected, keyActual);
                    break;
                }
            }
            // BouncyCastle's equals() only compares instances of the same class
            assertTrue(actual.equals(expected));
            break;

        case "XDH":
            if ((Runtime.version().version().get(0) < 16) && (encodedExpected.length != encodedActual.length)) {
                int actualOffset, expectedOffset;
                switch (actual.getFormat()) {
                case "PKCS#8":
                    // 3 bytes for version
                    actualOffset = 5;
                    expectedOffset = expected.getAlgorithm().equals("X25519") ? 12 : 13;
                    if (Runtime.version().version().get(0) == 11) {
                        // JDK bug https://bugs.openjdk.org/browse/JDK-8213363 - invalid XDH private
                        // key decoding and encoding
                        expectedOffset = expectedOffset + 2;
                    }
                    break;
                case "X.509":
                    actualOffset = 2;
                    expectedOffset = 9;
                    break;
                default:
                    throw new IllegalArgumentException(actual.getFormat());
                }
                byte[] encodedAlgorithm = Arrays.copyOfRange(encodedActual, actualOffset,
                        actualOffset + INVALID_X25519.length);

                if (Arrays.equals(encodedAlgorithm, INVALID_X25519) || Arrays.equals(encodedAlgorithm, INVALID_X448)) {
                    // JDK bug https://bugs.openjdk.org/browse/JDK-8252377 - null parameter in XDH
                    // algorithms
                    byte[] keyExpected = Arrays.copyOfRange(encodedExpected, expectedOffset, encodedExpected.length);
                    byte[] keyActual = Arrays.copyOfRange(encodedActual, actualOffset + INVALID_X25519.length,
                            encodedActual.length);
                    if (actual.getFormat().equals("PKCS#8") && (keyExpected.length > keyActual.length)) {
                        // ignore public key - PKCS#8 version 1 supported since JDK 15
                        // https://bugs.openjdk.org/browse/JDK-8244565
                        keyExpected = Arrays.copyOfRange(keyExpected, 0, keyActual.length);
                    }
                    assertArrayEquals(keyExpected, keyActual);
                    break;
                }
            }
            /* no break */

        default:
            assertEquals(expected, actual);
        }
    }

}
