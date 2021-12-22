package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertFalse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
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
        "Policy",
        "SecureRandom",
        "Signature"
    })
    public void testGetAlgorithms(String serviceType) {
        assertFalse(Algorithms.getAlgorithms(serviceType).isEmpty());
    }

    @Test
    public void testGetCertificateProviderNames() {
        for (String algorithm : Algorithms.getCertificateAlgorithms()) {
            assertFalse(Algorithms.getCertificateProviderNames(algorithm).isEmpty());
        }
    }

    @Test
    public void testGetKeyProviderNames() {
        for (String algorithm : Algorithms.getKeyAlgorithms()) {
            assertFalse(Algorithms.getKeyProviderNames(algorithm).isEmpty());
        }
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
        "Policy",
        "SecureRandom",
        "Signature"
    })
    public void testGetProviderNames(String serviceType) {
        for (String algorithm : Algorithms.getAlgorithms(serviceType)) {
            assertFalse(Algorithms.getProviderNames(serviceType, algorithm).isEmpty());
        }
    }

}
