package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.XECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import javax.crypto.interfaces.DHKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class KeyPairBuilderTest {

    @Test
    public void testDefault() throws Exception {
        KeyPair keyPair = KeyPairBuilder.defaultKeyPair();

        assertAll(
            () -> assertEquals(Defaults.getKeyAlgorithm(), keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals(Defaults.getKeyAlgorithm(), keyPair.getPublic().getAlgorithm()),
            () -> assertEquals(Defaults.getKeySize(), getSize(keyPair.getPrivate())),
            () -> assertEquals(Defaults.getKeySize(), getSize(keyPair.getPublic()))
        );
    }

    @ParameterizedTest
    @CsvSource({
        "DH,   512, javax.crypto.interfaces.DHKey",
        "DSA, 1024, java.security.interfaces.DSAKey",
        "EC,   384, java.security.interfaces.ECKey",
        "RSA, 4096, java.security.interfaces.RSAKey",
        "XDH,  255, java.security.interfaces.XECKey",
        "XDH,  448, java.security.interfaces.XECKey"
    })
    public void testWithSize(String algorithm, int keySize, Class<? extends Key> keyClass)
            throws Exception {
        KeyPairBuilder builder = new KeyPairBuilder()
            .withAlgorithm(algorithm)
            .withSize(keySize);
        KeyPair keyPair = builder.build();

        assertAll(
            () -> assertTrue(keyClass.isInstance(keyPair.getPrivate())),
            () -> assertTrue(keyClass.isInstance(keyPair.getPublic())),
            () -> assertEquals(builder.algorithm, keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals(builder.algorithm, keyPair.getPublic().getAlgorithm()),
            () -> assertEquals(builder.size, getSize(keyPair.getPrivate())),
            () -> assertEquals(builder.size, getSize(keyPair.getPublic()))
        );
    }

    protected static int getSize(Key key) {
        if (key instanceof DHKey) {
            return ((DHKey) key).getParams().getP().bitLength();
        }
        if (key instanceof DSAKey) {
            return ((DSAKey) key).getParams().getP().bitLength();
        }
        if (key instanceof ECKey) {
            return ((ECKey) key).getParams().getCurve().getA().bitLength();
        }
        if (key instanceof RSAKey) {
            return ((RSAKey) key).getModulus().bitLength();
        }
        if (key instanceof XECKey) {
            switch (((NamedParameterSpec) ((XECKey) key).getParams()).getName()) {
                case "X25519":
                    return 255;
                case "X448":
                    return 448;
            }
        }
        throw new IllegalArgumentException(key.getClass().getName());
    }

    @ParameterizedTest
    @CsvSource({
        "secp112r1,             1.3.132.0.6",
        "1.3.132.0.7,           1.3.132.0.7",
        "secp384r1,             1.3.132.0.34",
        "secp521r1,             1.3.132.0.35",
        "NIST K-571,            1.3.132.0.38",
        "sect571r1,             1.3.132.0.39",
        "X9.62 c2tnb191v1,      1.2.840.10045.3.0.5",
        "1.2.840.10045.3.0.6,   1.2.840.10045.3.0.6",
        "X9.62 c2tnb359v1,      1.2.840.10045.3.0.18",
        "X9.62 c2tnb431r1,      1.2.840.10045.3.0.20",
        "X9.62 prime192v2,      1.2.840.10045.3.1.2",
        "X9.62 prime239v3,      1.2.840.10045.3.1.6",
        "secp256r1,             1.2.840.10045.3.1.7"
    })
    public void testWithParamsEC(String stdName, String OID)
            throws Exception {
        KeyPairBuilder builder = new KeyPairBuilder()
            .withParams(new ECGenParameterSpec(stdName));
        KeyPair keyPair = builder.build();

        assertAll(
            () -> assertTrue(ECPrivateKey.class.isInstance(keyPair.getPrivate())),
            () -> assertTrue(ECPublicKey.class.isInstance(keyPair.getPublic())),
            () -> assertEquals("EC", keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals("EC", keyPair.getPublic().getAlgorithm())
        );
    }

}
