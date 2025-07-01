package com.github.jss;

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Algorithms {

    private enum KnownAlgorithms {
        DH("1.2.840.10046.2.1"),
        DSA("1.2.840.10040.4.1"),
        EC("1.2.840.10045.2.1"),
        ED25519("1.3.101.112"),
        ED448("1.3.101.113"),
        RSA("1.2.840.113549.1.1.1"),
        X25519("1.3.101.110"),
        X448("1.3.101.111");

        final String oid;

        KnownAlgorithms(String oid) {
            this.oid = oid;
        }

        String getOid() {
            return oid;
        }
    }

    private static final Map<String, String> OID_TO_NAME = Stream.of(KnownAlgorithms.values())
            .collect(Collectors.toMap(KnownAlgorithms::getOid, KnownAlgorithms::name));

    private static final Set<String> KNOWN_NAMES = Stream.of(KnownAlgorithms.values())
            .map(KnownAlgorithms::name)
            .collect(Collectors.toSet());

    private static final Comparator<String> NAME_COMPARATOR = new Comparator<>() {
        @Override
        public int compare(String arg1, String arg2) {
            String _default = Defaults.getKeyAlgorithm();
            if (_default.equals(arg1)) {
                return -1;
            }
            if (_default.equals(arg2)) {
                return 1;
            }

            boolean top1 = KNOWN_NAMES.contains(arg1);
            boolean top2 = KNOWN_NAMES.contains(arg2);
            if (top1 && !top2) {
                return -1;
            }
            if (!top1 && top2) {
                return 1;
            }

            return Objects.compare(arg1, arg2, String::compareTo);
        }
    };

    public static List<String> getCertificateAlgorithms() {
        return getAlgorithms(CertificateFactory.class.getSimpleName());
    }

    public static List<String> getKeyAlgorithms() {
        return getAlgorithms(KeyPairGenerator.class.getSimpleName());
    }

    public static List<String> getAlgorithms(String serviceType) {
        return Security.getAlgorithms(serviceType).stream()
            .sorted(NAME_COMPARATOR)
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

    static Optional<String> findByOid(String oid) {
        return Optional.ofNullable(OID_TO_NAME.get(oid));
    }

}
