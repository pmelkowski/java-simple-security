package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.XECKey;
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
    public void test(String algorithm, int keySize, Class<? extends Key> keyClass) throws Exception {
        KeyPairBuilder builder = new KeyPairBuilder()
            .withAlgorithm(algorithm)
            .withSize(keySize);
        KeyPair keyPair = builder.build();
        assertAll(
            () -> assertTrue(keyClass.isInstance(keyPair.getPrivate())),
            () -> assertTrue(keyClass.isInstance(keyPair.getPublic())),
            () -> commonChecks(builder, keyPair)
        );
    }

    protected static void commonChecks(KeyPairBuilder builder, KeyPair keyPair) {
        assertAll(
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

}
