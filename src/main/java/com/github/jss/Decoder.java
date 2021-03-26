package com.github.jss;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Decoder {

    public static PrivateKey decodePrivateKey(String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return decodePrivateKey(Defaults.getKeyAlgorithm(), encodedString);
    }

    public static PrivateKey decodePrivateKey(String algorithm, String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance(algorithm).generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedString)));
    }

    public static PublicKey decodePublicKey(String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return decodePublicKey(Defaults.getKeyAlgorithm(), encodedString);
    }

    public static PublicKey decodePublicKey(String algorithm, String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance(algorithm).generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(encodedString)));
    }

    public static X509Certificate decodeX509Certificate(String encodedString)
            throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(encodedString.getBytes())));
    }

}
