package com.github.jss;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CertUtils {

    private static final AlgorithmId SIGNING_ALGORITHM = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);

    public static X509Certificate generateSelfSignedCertificate(String subjectName, KeyPair keyPair, int yearsToExpire)
            throws CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException {
        ZonedDateTime now = ZonedDateTime.now();
        Date notBefore = Date.from(now.toInstant());
        Date notAfter = Date.from(now.plusYears(yearsToExpire).toInstant());

        BigInteger serial = new BigInteger(Long.toString(notBefore.getTime()));
        X500Name subject = new X500Name(subjectName);

        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(notBefore, notAfter));
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serial));
        info.set(X509CertInfo.SUBJECT, subject);
        info.set(X509CertInfo.ISSUER, subject);
        info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(SIGNING_ALGORITHM));

        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(keyPair.getPrivate(), SIGNING_ALGORITHM.getName());

        return certificate;
    }

    public static String getPEMString(Certificate certificate) throws CertificateEncodingException {
        return Stream.of(
                    Stream.of("-----BEGIN CERTIFICATE-----"),
                    Stream.of(encode(certificate).split("(?<=\\G.{64})")),
                    Stream.of("-----END CERTIFICATE-----")
                ).flatMap(Function.identity())
            .collect(Collectors.joining("\n"));
    }

    public static String encode(Certificate certificate) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

}
