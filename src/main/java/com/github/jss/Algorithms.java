package com.github.jss;

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Algorithms {

    public static List<String> getCertificateAlgorithms() {
        return getAlgorithms(CertificateFactory.class.getSimpleName());
    }

    public static List<String> getKeyAlgorithms() {
        return getAlgorithms(KeyPairGenerator.class.getSimpleName());
    }

    public static List<String> getAlgorithms(String serviceType) {
        return Security.getAlgorithms(serviceType).stream()
            .collect(Collectors.toList());
    }

    public static List<String> getCertificateProviderNames(String algorithm) {
        return getProviderNames(CertificateFactory.class.getSimpleName(), algorithm);
    }

    public static List<String> getKeyProviderNames(String algorithm) {
        return getProviderNames(KeyPairGenerator.class.getSimpleName(), algorithm);
    }

    public static List<String> getProviderNames(String serviceType, String algorithm) {
        return Optional.ofNullable(Security.getProviders(serviceType + "." + algorithm))
            .map(Stream::of)
            .orElseGet(Stream::empty)
            .map(Provider::getName)
            .collect(Collectors.toList());
    }

}
