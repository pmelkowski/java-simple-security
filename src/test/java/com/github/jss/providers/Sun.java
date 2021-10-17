package com.github.jss.providers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class Sun extends Provider {

    public Sun() {
        super(List.of("SUN", "SunJSSE", "SunJCE", "SunEC"));
    }

    @Override
    public X509Certificate getX509Certificate(PublicKey subjectKey, PrivateKey issuerKey, int version,
            int validityAmount, ChronoUnit validityUnit, BigInteger serialNumber,
            String signingAlgorithm) throws NoSuchAlgorithmException, CertificateException,
            IOException, InvalidKeyException, NoSuchProviderException, SignatureException {
        AlgorithmId signingAlgorithmId = AlgorithmId.get(signingAlgorithm);

        ZonedDateTime now = ZonedDateTime.now();
        Date notBefore = Date.from(now.toInstant());
        Date notAfter = Date.from(now.plus(validityAmount, validityUnit).toInstant());

        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(signingAlgorithmId));
        info.set(X509CertInfo.ISSUER, new X500Name(ISSUER.getName()));
        info.set(X509CertInfo.KEY, new CertificateX509Key(subjectKey));
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        info.set(X509CertInfo.SUBJECT, new X500Name(SUBJECT.getName()));
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(notBefore, notAfter));
        info.set(X509CertInfo.VERSION, new CertificateVersion(version));

        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(issuerKey, signingAlgorithmId.getName());
        return certificate;
    }

    @Override
    public String encodeToPEM(Object obj) throws Exception {
        throw new UnsupportedOperationException();
    }

    @Override
    public PrivateKey decodePrivateKeyPEM(String pem) throws Exception {
        throw new UnsupportedOperationException();
    }

    @Override
    public PublicKey decodePublicKeyPEM(String pem) throws Exception {
        throw new UnsupportedOperationException();
    }

}
