package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Key;
import java.security.cert.Certificate;
import java.util.Arrays;

public class Assertions {

    private static byte[] INVALID_X25519 = new byte[] {48, 7, 6, 3, 43, 101, 110, 5, 0};
    private static byte[] INVALID_X448 =   new byte[] {48, 7, 6, 3, 43, 101, 111, 5, 0};

    public static void assertKeyEquals(Key expected, Key actual) {
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

    public static void assertCertificateEquals(Certificate expected, Certificate actual) {
        assertAll(
            () -> assertEquals(expected, actual),
            () -> assertKeyEquals(expected.getPublicKey(), actual.getPublicKey())
        );
    }

}
