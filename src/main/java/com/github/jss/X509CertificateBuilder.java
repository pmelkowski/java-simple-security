package com.github.jss;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
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
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAdjuster;
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

    static {
        JavaBaseModule.addExports("sun.security.x509");
    }

    protected static final DateTimeFormatter SERIAL_FORMATTER = new DateTimeFormatterBuilder()
        .appendValue(ChronoField.YEAR, 4)
        .appendValue(ChronoField.MONTH_OF_YEAR, 2)
        .appendValue(ChronoField.DAY_OF_MONTH, 2)
        .appendValue(ChronoField.HOUR_OF_DAY, 2)
        .appendValue(ChronoField.MINUTE_OF_HOUR, 2)
        .appendValue(ChronoField.SECOND_OF_MINUTE, 2)
        .appendFraction(ChronoField.NANO_OF_SECOND, 9, 9, false)
        .toFormatter();

    protected final X500Name subject;
    protected final X500Name issuer;
    protected final PublicKey subjectKey;
    protected final PrivateKey issuerKey;

    protected Instant notBefore;
    protected Instant notAfter;
    protected BigInteger serialNumber;
    protected CertificateVersion version;
    protected AlgorithmId signingAlgorithm;

    public X509CertificateBuilder(String subject, KeyPair keyPair) throws IOException {
        this(subject, subject, keyPair.getPublic(), keyPair.getPrivate());
    }

    public X509CertificateBuilder(String subject, String issuer, PublicKey subjectKey,
            PrivateKey issuerKey) throws IOException {
        this.subject = new X500Name(subject);
        this.issuer = new X500Name(issuer);
        this.subjectKey = subjectKey;
        this.issuerKey = issuerKey;
    }

    public X509CertificateBuilder withNotBefore(Instant notBefore) {
        this.notBefore = notBefore;
        return this;
    }

    public X509CertificateBuilder withNotBefore(TemporalAdjuster notBefore) {
        this.notBefore = ZonedDateTime.now().with(notBefore).toInstant();
        return this;
    }

    public X509CertificateBuilder withNotBefore(Date notBefore) {
        this.notBefore = notBefore.toInstant();
        return this;
    }

    public X509CertificateBuilder withNotAfter(Instant notAfter) {
        this.notAfter = notAfter;
        return this;
    }

    public X509CertificateBuilder withNotAfter(TemporalAdjuster notAfter) {
        this.notAfter = ZonedDateTime.now().with(notAfter).toInstant();
        return this;
    }

    public X509CertificateBuilder withNotAfter(Date notAfter) {
        this.notAfter = notAfter.toInstant();
        return this;
    }

    public X509CertificateBuilder withValidity(long amount, TemporalUnit unit) {
        if (notBefore == null) {
            notBefore = Instant.now();
        }
        notAfter = ZonedDateTime.now().with(notBefore).plus(amount, unit).toInstant();
        return this;
    }

    public X509CertificateBuilder withSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    public X509CertificateBuilder withSerialNumber(long serialNumber) {
        this.serialNumber = new BigInteger(Long.toString(serialNumber));
        return this;
    }

    public X509CertificateBuilder withSerialNumber(TemporalAdjuster serialNumber) {
        this.serialNumber = new BigInteger(SERIAL_FORMATTER.format(
                ZonedDateTime.now().with(serialNumber)));
        return this;
    }

    public X509CertificateBuilder withSerialNumber(Date serialNumber) {
        return withSerialNumber(serialNumber.toInstant());
    }

    public X509CertificateBuilder withVersion(int version) throws IOException {
        this.version = new CertificateVersion(version);
        return this;
    }

    public X509CertificateBuilder withSigningAlgorithm(String signingAlgorithm) throws NoSuchAlgorithmException {
        this.signingAlgorithm = AlgorithmId.get(signingAlgorithm);
        return this;
    }

    public X509Certificate build() throws CertificateException, IOException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        Instant now = Instant.now();
        if (notBefore == null) {
            withNotBefore(now);
        }
        if (notAfter == null) {
            withValidity(Defaults.getCertificateValidityAmount(), Defaults.getCertificateValidityUnit());
        }
        if (serialNumber == null) {
            withSerialNumber(now);
        }
        if (version == null) {
            withVersion(Defaults.getCertificateVersion());
        }
        if (signingAlgorithm == null) {
            withSigningAlgorithm(Defaults.getSigningAlgorithm());
        }

        X509CertInfo info = new X509CertInfo();
        CertificateAlgorithmId algorithmId = new CertificateAlgorithmId(signingAlgorithm);
        CertificateX509Key certificateKey = new CertificateX509Key(subjectKey);
        CertificateSerialNumber certificateSN = new CertificateSerialNumber(serialNumber);
        CertificateValidity certificateValidity = new CertificateValidity(Date.from(notBefore), Date.from(notAfter));

        // Use reflection to handle various JRE versions
        try {
            if (Runtime.version().version().get(0) < 20) {
                Method setter = X509CertInfo.class.getMethod("set", String.class, Object.class);
                setter.invoke(info, X509CertInfo.ALGORITHM_ID, algorithmId);
                setter.invoke(info, X509CertInfo.ISSUER, issuer);
                setter.invoke(info, X509CertInfo.KEY, certificateKey);
                setter.invoke(info, X509CertInfo.SERIAL_NUMBER, certificateSN);
                setter.invoke(info, X509CertInfo.SUBJECT, subject);
                setter.invoke(info, X509CertInfo.VALIDITY, certificateValidity);
                setter.invoke(info, X509CertInfo.VERSION, version);

                X509CertImpl certificate = X509CertImpl.class.getConstructor(X509CertInfo.class).newInstance(info);
                X509CertImpl.class.getMethod("sign", PrivateKey.class, String.class)
                    .invoke(certificate, issuerKey, signingAlgorithm.getName());
                return certificate;
            } else {
                X509CertInfo.class.getMethod("setAlgorithmId", CertificateAlgorithmId.class)
                    .invoke(info, algorithmId);
                X509CertInfo.class.getMethod("setIssuer", X500Name.class)
                    .invoke(info, issuer);
                X509CertInfo.class.getMethod("setKey", CertificateX509Key.class)
                    .invoke(info, certificateKey);
                X509CertInfo.class.getMethod("setSerialNumber", CertificateSerialNumber.class)
                    .invoke(info, certificateSN);
                X509CertInfo.class.getMethod("setSubject", X500Name.class)
                    .invoke(info, subject);
                X509CertInfo.class.getMethod("setValidity", CertificateValidity.class)
                    .invoke(info, certificateValidity);
                X509CertInfo.class.getMethod("setVersion", CertificateVersion.class)
                    .invoke(info, version);

                return (X509Certificate) X509CertImpl.class.getMethod("newSigned",
                        X509CertInfo.class, PrivateKey.class, String.class)
                    .invoke(X509CertImpl.class, info, issuerKey, signingAlgorithm.getName());
            }
        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException
                | SecurityException | InstantiationException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
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
