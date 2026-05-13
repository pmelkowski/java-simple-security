package com.github.jss.providers;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;

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
        super(Set.of("SUN", "SunJSSE", "SunJCE", "SunRsaSign", "SunEC"));
    }

    @Override
	public X509Certificate getX509Certificate(PublicKey subjectKey, PrivateKey issuerKey, int version,
            int validityAmount, ChronoUnit validityUnit, BigInteger serialNumber, String signingAlgorithm)
            throws Exception {
        AlgorithmId signingAlgorithmId = AlgorithmId.get(signingAlgorithm);
        ZonedDateTime now = ZonedDateTime.now();
        Date notBefore = Date.from(now.toInstant());
        Date notAfter = Date.from(now.plus(validityAmount, validityUnit).toInstant());
        X509CertInfo info = new X509CertInfo();

        // Use reflection to handle various JRE versions
        if (Runtime.version().version().get(0) < 20) {
            Method setter = X509CertInfo.class.getMethod("set", String.class, Object.class);
            setter.invoke(info, X509CertInfo.ALGORITHM_ID,
                    new CertificateAlgorithmId(signingAlgorithmId));
            setter.invoke(info, X509CertInfo.ISSUER, new X500Name(ISSUER.getName()));
            setter.invoke(info, X509CertInfo.KEY, new CertificateX509Key(subjectKey));
            setter.invoke(info, X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
            setter.invoke(info, X509CertInfo.SUBJECT, new X500Name(SUBJECT.getName()));
            setter.invoke(info, X509CertInfo.VALIDITY, new CertificateValidity(notBefore, notAfter));
            setter.invoke(info, X509CertInfo.VERSION, new CertificateVersion(version));

            X509CertImpl certificate = X509CertImpl.class.getConstructor(X509CertInfo.class).newInstance(info);
            X509CertImpl.class.getMethod("sign", PrivateKey.class, String.class)
                .invoke(certificate, issuerKey, signingAlgorithmId.getName());
            return certificate;
        } else {
            X509CertInfo.class.getMethod("setAlgorithmId", CertificateAlgorithmId.class)
                .invoke(info, new CertificateAlgorithmId(signingAlgorithmId));
            X509CertInfo.class.getMethod("setIssuer", X500Name.class)
                .invoke(info, new X500Name(ISSUER.getName()));
            X509CertInfo.class.getMethod("setKey", CertificateX509Key.class)
                .invoke(info, new CertificateX509Key(subjectKey));
            X509CertInfo.class.getMethod("setSerialNumber", CertificateSerialNumber.class)
                .invoke(info, new CertificateSerialNumber(serialNumber));
            X509CertInfo.class.getMethod("setSubject", X500Name.class)
                .invoke(info, new X500Name(SUBJECT.getName()));
            X509CertInfo.class.getMethod("setValidity", CertificateValidity.class)
                .invoke(info, new CertificateValidity(notBefore, notAfter));
            X509CertInfo.class.getMethod("setVersion", CertificateVersion.class)
                .invoke(info, new CertificateVersion(version));

            return (X509Certificate) X509CertImpl.class.getMethod("newSigned",
                    X509CertInfo.class, PrivateKey.class, String.class)
                .invoke(X509CertImpl.class, info, issuerKey, signingAlgorithmId.getName());
        }
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
