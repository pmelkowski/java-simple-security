package com.github.jss;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class KeyUtils {

    public static String encode(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PrivateKey decodePrivateKey(String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return decodePrivateKey("RSA", encodedString);
    }

    public static PrivateKey decodePrivateKey(String algorithm, String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] encodedKey = Base64.getDecoder().decode(encodedString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

}
