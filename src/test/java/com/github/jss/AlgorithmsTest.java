package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.FieldSource;
import org.junit.jupiter.params.provider.MethodSource;

public class AlgorithmsTest {

	private static final List<String> SERVICES = List.of(
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
    );

    @Test
    public void testGetCertificateAlgorithms() {
        assertFalse(Algorithms.getCertificateAlgorithms().isEmpty());
    }

    @Test
    public void testGetKeyAlgorithms() {
        assertFalse(Algorithms.getKeyAlgorithms().isEmpty());
    }

    @Test
    public void testGetSignatureAlgorithms() {
        assertFalse(Algorithms.getSignatureAlgorithms().isEmpty());
    }

    @ParameterizedTest
    @FieldSource("SERVICES")
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
    @MethodSource("com.github.jss.Algorithms#getSignatureAlgorithms")
    public void testGetSignatureProviderNames(String algorithm) {
        assertFalse(Algorithms.getSignatureProviderNames(algorithm).isEmpty());
    }

    @ParameterizedTest
    @MethodSource("getServicesAndAlgorithms")
    public void testGetProviderNames(String serviceType, String algorithm) {
        assertFalse(Algorithms.getProviderNames(serviceType, algorithm).isEmpty());
    }

    private static Stream<Arguments> getServicesAndAlgorithms() {
        return SERVICES.stream()
            .flatMap(serviceType -> Algorithms.getAlgorithms(serviceType).stream()
                .map(algorithm -> Arguments.of(serviceType, algorithm)));
    }

}
