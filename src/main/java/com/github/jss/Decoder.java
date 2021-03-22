package com.github.jss;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Decoder {

    public static PrivateKey decodePrivateKey(String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return decodePrivateKey(Defaults.getKeyAlgorithm(), encodedString);
    }

    public static PrivateKey decodePrivateKey(String algorithm, String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance(algorithm).generatePrivate(getKeySpec(encodedString));
    }

    public static PublicKey decodePublicKey(String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return decodePublicKey(Defaults.getKeyAlgorithm(), encodedString);
    }

    public static PublicKey decodePublicKey(String algorithm, String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance(algorithm).generatePublic(getKeySpec(encodedString));
    }

    protected static PKCS8EncodedKeySpec getKeySpec(String encodedString) {
        byte[] encodedKey = Base64.getDecoder().decode(encodedString);
        return new PKCS8EncodedKeySpec(encodedKey);
    }

}
