package com.github.jss;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class X509CertificateBuilder {

    protected final X500Name subject;
    protected final X500Name issuer;
    protected final PublicKey subjectKey;
    protected final PrivateKey issuerKey;

    protected Date notBefore;
    protected Date notAfter;
    protected BigInteger serialNumber;
    protected int version = Defaults.getCertificateVersion();
    protected String signingAlgorithm = Defaults.getSigningAlgorithm();

    public X509CertificateBuilder(String subject, KeyPair keyPair) throws IOException {
        this(subject, subject, keyPair.getPublic(), keyPair.getPrivate());
    }

    public X509CertificateBuilder(String subject, String issuer, PublicKey subjectKey,
            PrivateKey issuerKey) throws IOException {
        this.subject = new X500Name(subject);
        this.issuer = new X500Name(issuer);
        this.subjectKey = subjectKey;
        this.issuerKey = issuerKey;
        withValidityFromNow(Defaults.getValidityAmount(), Defaults.getValidityUnit());
    }

    public X509CertificateBuilder withNotBefore(Date notBefore) {
        this.notBefore = notBefore;
        return this;
    }

    public X509CertificateBuilder withNotAfter(Date notAfter) {
        this.notAfter = notAfter;
        return this;
    }

    public X509CertificateBuilder withValidityFromNow(long amount, TemporalUnit unit) {
        ZonedDateTime now = ZonedDateTime.now();
        this.notBefore = Date.from(now.toInstant());
        this.notAfter = Date.from(now.plus(amount, unit).toInstant());
        return this;
    }

    public X509CertificateBuilder withSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    public X509CertificateBuilder withVersion(int version) {
        this.version = version;
        return this;
    }

    public X509CertificateBuilder withSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
        return this;
    }

    public X509Certificate build() throws CertificateException, IOException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        AlgorithmId signingAlgorithmId = AlgorithmId.get(signingAlgorithm);

        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(notBefore, notAfter));
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
                serialNumber != null ? serialNumber : new BigInteger(Long.toString(System.currentTimeMillis()))));
        info.set(X509CertInfo.SUBJECT, subject);
        info.set(X509CertInfo.ISSUER, issuer);
        info.set(X509CertInfo.KEY, new CertificateX509Key(subjectKey));
        info.set(X509CertInfo.VERSION, new CertificateVersion(version));
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(signingAlgorithmId));

        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(issuerKey, signingAlgorithmId.getName());
        return certificate;
    }

    public static X509Certificate defaultCertificate(String subject, String issuer, PublicKey subjectKey,
            PrivateKey issuerKey) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, IOException {
        return new X509CertificateBuilder(subject, issuer, subjectKey, issuerKey).build();
    }

    public static X509Certificate defaultSelfSignedCertificate(String subject, KeyPair keyPair)
            throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, IOException {
        return new X509CertificateBuilder(subject, keyPair).build();
    }

}
