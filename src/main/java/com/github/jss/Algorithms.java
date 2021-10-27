package com.github.jss;

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Algorithms {

    private static final Set<String> TOP_ALGORITHMS =
            Set.of("RSA", "DSA", "EC", "DH", "XDH");

    private static final Comparator<String> ALGORITHM_COMPARATOR = new Comparator<>() {
        @Override
        public int compare(String arg1, String arg2) {
            String _default = Defaults.getKeyAlgorithm();
            if (_default.equals(arg1)) {
                return -1;
            }
            if (_default.equals(arg2)) {
                return 1;
            }

            boolean top1 = TOP_ALGORITHMS.contains(arg1);
            boolean top2 = TOP_ALGORITHMS.contains(arg2);
            if (top1 && !top2) {
                return -1;
            }
            if (!top1 && top2) {
                return 1;
            }

            return Objects.compare(arg1, arg2, String::compareTo);
        }
    };

    public static List<String> getAlgorithms() {
        return getAlgorithms(KeyPairGenerator.class.getSimpleName());
    }

    public static List<String> getAlgorithms(String serviceType) {
        return Security.getAlgorithms(serviceType).stream()
            .sorted(ALGORITHM_COMPARATOR)
            .collect(Collectors.toList());
    }

    public static List<String> getProviderNames(String algorithm) {
        return getProviderNames(KeyPairGenerator.class.getSimpleName(), algorithm);
    }

    public static List<String> getProviderNames(String serviceType, String algorithm) {
        return Stream.of(Security.getProviders(serviceType + "." + algorithm))
            .map(Provider::getName)
            .collect(Collectors.toList());
    }

}
