package com.github.jss;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyPairBuilder {

    protected String algorithm = Defaults.getKeyAlgorithm();
    protected int size = Defaults.getKeySize();

    public KeyPairBuilder withAlgorithm(String alogrithm) {
        this.algorithm = alogrithm;
        return this;
    }

    public KeyPairBuilder withSize(int size) {
        this.size = size;
        return this;
    }

    public KeyPair build() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
        keyGen.initialize(size);
        return keyGen.generateKeyPair();
    }

    public static KeyPair defaultKeyPair() throws NoSuchAlgorithmException {
        return new KeyPairBuilder().build();
    }

}
