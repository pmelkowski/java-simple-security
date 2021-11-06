package com.github.jss;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAGenParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Map;
import java.util.Optional;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

public class KeyPairBuilder {

    protected static final Map<Class<? extends AlgorithmParameterSpec>, String>
            PARAM_ALGORITHMS = Map.of(
                    DHGenParameterSpec.class, "DH",
                    DHParameterSpec.class, "DH",
                    DSAGenParameterSpec.class, "DSA",
                    DSAParameterSpec.class, "DSA",
                    ECGenParameterSpec.class, "EC",
                    ECParameterSpec.class, "EC",
                    RSAKeyGenParameterSpec.class, "RSA"
            );

    protected String algorithm = Defaults.getKeyAlgorithm();
    protected int size = Defaults.getKeySize();
    protected AlgorithmParameterSpec params;
    protected SecureRandom random;

    public KeyPairBuilder withAlgorithm(String alogrithm) {
        this.algorithm = alogrithm;
        return this;
    }

    public KeyPairBuilder withSize(int size) {
        this.size = size;
        return this;
    }

    public KeyPairBuilder withParams(AlgorithmParameterSpec params) {
        this.params = params;
        return this;
    }

    public KeyPairBuilder withRandom(SecureRandom random) {
        this.random = random;
        return this;
    }

    public KeyPair build() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(
                getAlgorithm(params).orElse(algorithm));

        if (params != null) {
            if (random != null) {
                keyGen.initialize(params, random);
            } else {
                keyGen.initialize(params);
            }
        } else {
            if (random != null) {
                keyGen.initialize(size, random);
            } else {
                keyGen.initialize(size);
            }
        }

        return keyGen.generateKeyPair();
    }

    public static KeyPair defaultKeyPair()
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return new KeyPairBuilder().build();
    }

    protected static Optional<String> getAlgorithm(AlgorithmParameterSpec params) {
        if (params == null) {
            return Optional.empty();
        }
        return PARAM_ALGORITHMS.entrySet().stream()
            .filter(entry -> entry.getKey().isAssignableFrom(params.getClass()))
            .findAny()
            .map(Map.Entry::getValue);
    }

}
