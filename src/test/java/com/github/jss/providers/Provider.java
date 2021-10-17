package com.github.jss.providers;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import javax.security.auth.x500.X500Principal;

abstract public class Provider {

    static final X500Principal SUBJECT =
            new X500Principal("O=GitHub, OU=SimpleJavaSecurity, CN=subject");
    static final X500Principal ISSUER =
            new X500Principal("O=GitHub, OU=SimpleJavaSecurity, CN=issuer");

    private final List<String> providerNames;

    Provider(List<String> providerNames) {
        this.providerNames = providerNames;
    }

    @FunctionalInterface
    private interface ServiceBiFunction<SERVICE> {
        SERVICE find(String type, String provider) throws Exception;
    }

    private <SERVICE> SERVICE findService(ServiceBiFunction<SERVICE> service, String type)
            throws Exception {
        for (String provider : providerNames) {
            try {
                return service.find(type, provider);
            } catch (Exception e) {
            }
        }
        throw new IllegalArgumentException(type);
    }

    public KeyPair getKeyPair(String algorithm, int keySize) throws Exception {
        KeyPairGenerator keyGen = findService(KeyPairGenerator::getInstance, algorithm);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    public String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public PrivateKey decodePrivateKey(String algorithm, String encoded) throws Exception {
        KeyFactory keyFactory = findService(KeyFactory::getInstance, algorithm);
        return keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded)));
    }

    public PublicKey decodePublicKey(String algorithm, String encoded) throws Exception {
        KeyFactory keyFactory = findService(KeyFactory::getInstance, algorithm);
        return keyFactory.generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(encoded)));
    }

    abstract public X509Certificate getX509Certificate(PublicKey subjectKey, PrivateKey issuerKey,
            int version, int validityAmount, ChronoUnit validityUnit, BigInteger serialNumber,
            String signingAlgorithm) throws Exception;

    public String encodeCertificate(Certificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    public Certificate decodeCertificate(String type, String encoded) throws Exception {
        CertificateFactory certFactory = findService(CertificateFactory::getInstance, type);
        return certFactory.generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
    }
 
    abstract public String encodeToPEM(Object obj) throws Exception;

    abstract public PrivateKey decodePrivateKeyPEM(String pem) throws Exception;

    abstract public PublicKey decodePublicKeyPEM(String pem) throws Exception;

    public Certificate decodeCertificatePEM(String type, String pem) throws Exception {
        CertificateFactory certFactory = findService(CertificateFactory::getInstance, type);
        return certFactory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes()));
    }

}
