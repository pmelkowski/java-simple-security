package com.github.jss;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

class TestUtils {
    static final X500Principal SUBJECT =
            new X500Principal("O=GitHub, OU=SimpleJavaSecurity, CN=subject");
    static final X500Principal ISSUER =
            new X500Principal("O=GitHub, OU=SimpleJavaSecurity, CN=issuer");

    static KeyPair getKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    static Certificate getCertificate(PublicKey subjectKey, PrivateKey issuerKey, int version,
            int validityAmount, ChronoUnit validityUnit, BigInteger serialNumber,
            String signingAlgorithm) throws NoSuchAlgorithmException, CertificateException,
            IOException, InvalidKeyException, NoSuchProviderException, SignatureException {
        AlgorithmId signingAlgorithmId = AlgorithmId.get(signingAlgorithm);

        ZonedDateTime now = ZonedDateTime.now();

        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(signingAlgorithmId));
        info.set(X509CertInfo.ISSUER, new X500Name(TestUtils.ISSUER.getName()));
        info.set(X509CertInfo.KEY, new CertificateX509Key(subjectKey));
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        info.set(X509CertInfo.SUBJECT, new X500Name(TestUtils.SUBJECT.getName()));
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(Date.from(now.toInstant()),
                Date.from(now.plus(validityAmount, validityUnit).toInstant())));
        info.set(X509CertInfo.VERSION, new CertificateVersion(version));

        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(issuerKey, signingAlgorithmId.getName());
        return certificate;
    }

}
