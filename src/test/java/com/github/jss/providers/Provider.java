package com.github.jss.providers;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import com.github.jss.Algorithms;

abstract public class Provider {

    static final X500Principal SUBJECT =
            new X500Principal("O=GitHub, OU=SimpleJavaSecurity, CN=subject");
    static final X500Principal ISSUER =
            new X500Principal("O=GitHub, OU=SimpleJavaSecurity, CN=issuer");

    private final Set<String> providerNames;

    Provider(Set<String> providerNames) {
        this.providerNames = providerNames;
    }

    protected <SERVICE> SERVICE findService(Class<SERVICE> service, String algorithm)
            throws Exception {
        String provider = Algorithms.getProviderNames(service.getSimpleName(), algorithm).stream()
            .filter(providerNames::contains)
            .findFirst()
            .orElseThrow(() -> new NoSuchAlgorithmException(algorithm));
        return service.cast(
                service.getDeclaredMethod("getInstance", String.class, String.class)
                    .invoke(null, algorithm, provider));
    }

    public KeyPair getKeyPair(String algorithm, int keySize) throws Exception {
        KeyPairGenerator keyGen = findService(KeyPairGenerator.class, algorithm);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    public String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public PrivateKey decodePrivateKey(String algorithm, String encoded) throws Exception {
        return decodePrivateKey(algorithm, Base64.getDecoder().decode(encoded));
    }

    protected PrivateKey decodePrivateKey(String algorithm, byte[] encoded) throws Exception {
        KeyFactory keyFactory = findService(KeyFactory.class, algorithm);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    public PublicKey decodePublicKey(String algorithm, String encoded) throws Exception {
        return decodePublicKey(algorithm, Base64.getDecoder().decode(encoded));
    }

    protected PublicKey decodePublicKey(String algorithm, byte[] encoded) throws Exception {
        KeyFactory keyFactory = findService(KeyFactory.class, algorithm);
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    abstract public X509Certificate getX509Certificate(PublicKey subjectKey, PrivateKey issuerKey,
            int version, int validityAmount, ChronoUnit validityUnit, BigInteger serialNumber,
            String signingAlgorithm) throws Exception;

    public String encodeCertificate(Certificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    public Certificate decodeCertificate(String algorithm, String encoded) throws Exception {
        CertificateFactory certFactory = findService(CertificateFactory.class, algorithm);
        return certFactory.generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
    }
 
    abstract public String encodeToPEM(Object obj) throws Exception;

    abstract public PrivateKey decodePrivateKeyPEM(String pem) throws Exception;

    abstract public PublicKey decodePublicKeyPEM(String pem) throws Exception;

    public Certificate decodeCertificatePEM(String algorithm, String pem) throws Exception {
        CertificateFactory certFactory = findService(CertificateFactory.class, algorithm);
        return certFactory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes()));
    }

    public boolean equals(Key key1, Key key2) throws Exception {
        return Objects.equals(key1, key2);
    }

}
