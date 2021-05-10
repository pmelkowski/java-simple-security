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
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.chrono.ChronoLocalDate;
import java.time.chrono.ChronoLocalDateTime;
import java.time.chrono.ChronoZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.time.temporal.Temporal;
import java.time.temporal.TemporalQuery;
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

    protected static final TemporalQuery<ChronoZonedDateTime<?>> ZONED_QUERY = (temporal) -> {
        if (temporal instanceof Instant) {
            return ((Instant) temporal).atZone(ZoneId.systemDefault());
        }
        if (temporal instanceof ChronoLocalDate) {
            temporal = ((ChronoLocalDate) temporal).atTime(LocalTime.MIN);
        }
        if (temporal instanceof ChronoLocalDateTime<?>) {
            temporal = ((ChronoLocalDateTime<?>) temporal).atZone(ZoneId.systemDefault());
        }
        if (temporal instanceof ChronoZonedDateTime<?>) {
            return (ChronoZonedDateTime<?>) temporal;
        }
        throw new IllegalArgumentException("Unsupported temporal " + temporal.getClass().getName());
    };

    protected static final DateTimeFormatter INSTANT_FORMATTER = new DateTimeFormatterBuilder()
        .appendValue(ChronoField.INSTANT_SECONDS, 10)
        .appendFraction(ChronoField.NANO_OF_SECOND, 9, 9, false)
        .toFormatter();

    protected static final DateTimeFormatter TEMPORAL_FORMATTER = new DateTimeFormatterBuilder()
        .appendValue(ChronoField.YEAR, 4)
        .appendValue(ChronoField.MONTH_OF_YEAR, 2)
        .appendValue(ChronoField.DAY_OF_MONTH, 2)
        .optionalStart()
        .appendValue(ChronoField.HOUR_OF_DAY, 2)
        .appendValue(ChronoField.MINUTE_OF_HOUR, 2)
        .appendValue(ChronoField.SECOND_OF_MINUTE, 2)
        .optionalEnd()
        .optionalStart()
        .appendFraction(ChronoField.NANO_OF_SECOND, 9, 9, false)
        .optionalEnd()
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

    public X509CertificateBuilder withNotBefore(Temporal notBefore) {
        this.notBefore = notBefore.query(ZONED_QUERY).toInstant();
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

    public X509CertificateBuilder withNotAfter(Temporal notAfter) {
        this.notBefore = notAfter.query(ZONED_QUERY).toInstant();
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
        notAfter = notBefore.query(ZONED_QUERY).plus(amount, unit).toInstant();
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

    public X509CertificateBuilder withSerialNumber(Instant serialNumber) {
        this.serialNumber = new BigInteger(INSTANT_FORMATTER.format(serialNumber));
        return this;
    }

    public X509CertificateBuilder withSerialNumber(Temporal serialNumber) {
        this.serialNumber = new BigInteger(TEMPORAL_FORMATTER.format(serialNumber));
        return this;
    }

    public X509CertificateBuilder withSerialNumber(Date serialNumber) {
        this.serialNumber = new BigInteger(TEMPORAL_FORMATTER.format(
                serialNumber.toInstant().query(ZONED_QUERY)));
        return this;
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
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(signingAlgorithm));
        info.set(X509CertInfo.ISSUER, issuer);
        info.set(X509CertInfo.KEY, new CertificateX509Key(subjectKey));
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        info.set(X509CertInfo.SUBJECT, subject);
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(Date.from(notBefore), Date.from(notAfter)));
        info.set(X509CertInfo.VERSION, version);

        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(issuerKey, signingAlgorithm.getName());
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
