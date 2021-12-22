package com.github.jss;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;

public class Encoder {

    public static String encode(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String encode(Certificate certificate) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    public static String encodeToPEM(PrivateKey key) {
        return new PEM(PEM.Type.PRIVATE_KEY, key.getEncoded()).toString();
    }

    public static String encodeToPEM(PublicKey key) {
        return new PEM(PEM.Type.PUBLIC_KEY, key.getEncoded()).toString();
    }

    public static String encodeToPEM(Certificate certificate) throws CertificateEncodingException {
        return new PEM(PEM.Type.CERTIFICATE, certificate.getEncoded()).toString();
    }

}
