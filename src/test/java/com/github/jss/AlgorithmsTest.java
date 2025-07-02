package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertFalse;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

public class AlgorithmsTest {

    @Test
    public void testGetCertificateAlgorithms() {
        assertFalse(Algorithms.getCertificateAlgorithms().isEmpty());
    }

    @Test
    public void testGetKeyAlgorithms() {
        assertFalse(Algorithms.getKeyAlgorithms().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "AlgorithmParameters",
        "AlgorithmParameterGenerator",
        "CertificateFactory",
        "CertPathBuilder",
        "CertPathValidator",
        "CertStore",
        "Configuration",
        "KeyFactory",
        "KeyPairGenerator",
        "KeyStore",
        "MessageDigest",
        "SecureRandom",
        "Signature"
    })
    public void testGetAlgorithms(String serviceType) {
        assertFalse(Algorithms.getAlgorithms(serviceType).isEmpty());
    }

    @ParameterizedTest
    @MethodSource("com.github.jss.Algorithms#getCertificateAlgorithms")
    public void testGetCertificateProviderNames(String algorithm) {
        assertFalse(Algorithms.getCertificateProviderNames(algorithm).isEmpty());
    }

    @ParameterizedTest
    @MethodSource("com.github.jss.Algorithms#getKeyAlgorithms")
    public void testGetKeyProviderNames(String algorithm) {
        assertFalse(Algorithms.getKeyProviderNames(algorithm).isEmpty());
    }

    @ParameterizedTest
    @MethodSource("getServicesAndAlgorithms")
    public void testGetProviderNames(String serviceType, String algorithm) {
        assertFalse(Algorithms.getProviderNames(serviceType, algorithm).isEmpty());
    }

    private static Stream<Arguments> getServicesAndAlgorithms() {
        return Stream.of(
                "AlgorithmParameters",
                "AlgorithmParameterGenerator",
                "CertificateFactory",
                "CertPathBuilder",
                "CertPathValidator",
                "CertStore",
                "Configuration",
                "KeyFactory",
                "KeyPairGenerator",
                "KeyStore",
                "MessageDigest",
                "Policy",
                "SecureRandom",
                "Signature")
            .flatMap(serviceType -> Algorithms.getAlgorithms(serviceType).stream()
                .map(algorithm -> Arguments.of(serviceType, algorithm)));
    }

}
