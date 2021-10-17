package com.github.jss;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Decoder {

    private static final Pattern PEM_PATTERN = Pattern.compile(
            "\\s*-+BEGIN ([A-Z\\s]+)-+((?s).*?)-+END ([A-Z\\s]+)-+\\s*", Pattern.MULTILINE);

    private static String stripPEM(String type, String encodedString) {
        Matcher matcher = PEM_PATTERN.matcher(encodedString);
        if (!matcher.matches()) {
            return encodedString;
        }

        String begin = matcher.group(1).trim();
        String end = matcher.group(3).strip();
        if (!begin.equals(end)) {
            throw new IllegalArgumentException("Invalid PEM");
        }
        if (!begin.endsWith(type)) {
            throw new IllegalArgumentException("Invalid PEM");
        }

        return matcher.group(2).replaceAll("\\s", "");
    }

    public static PrivateKey decodePrivateKey(String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return decodePrivateKey(Defaults.getKeyAlgorithm(), encodedString);
    }

    public static PrivateKey decodePrivateKey(String algorithm, String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        encodedString = stripPEM("PRIVATE KEY", encodedString);
        return KeyFactory.getInstance(algorithm).generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedString)));
    }

    public static PublicKey decodePublicKey(String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return decodePublicKey(Defaults.getKeyAlgorithm(), encodedString);
    }

    public static PublicKey decodePublicKey(String algorithm, String encodedString)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        encodedString = stripPEM("PUBLIC KEY", encodedString);
        return KeyFactory.getInstance(algorithm).generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(encodedString)));
    }

    public static X509Certificate decodeCertificate(String encodedString)
            throws CertificateException {
        return (X509Certificate) decodeCertificate("X.509", encodedString);
    }

    public static Certificate decodeCertificate(String type, String encodedString)
            throws CertificateException {
        byte[] encoded = encodedString.getBytes();
        if (!PEM_PATTERN.matcher(encodedString).matches()) {
            encoded = Base64.getDecoder().decode(encoded);
        }
        return CertificateFactory.getInstance(type).generateCertificate(
                new ByteArrayInputStream(encoded));
    }

}
