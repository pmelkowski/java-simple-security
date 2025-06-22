package com.github.jss.providers;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.security.x509.CertificateVersion;

public class BouncyCastle extends Provider {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final JcaPEMKeyConverter KEY_CONVERTER = new JcaPEMKeyConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME);

    public BouncyCastle() {
        super(Set.of(BouncyCastleProvider.PROVIDER_NAME));
    }

    @Override
    public X509Certificate getX509Certificate(PublicKey subjectKey, PrivateKey issuerKey,
            int version, int validityAmount, ChronoUnit validityUnit, BigInteger serialNumber,
            String signingAlgorithm) throws NoSuchAlgorithmException, OperatorCreationException,
            CertificateException {
        ZonedDateTime now = ZonedDateTime.now();
        Date notBefore = Date.from(now.toInstant());
        Date notAfter = Date.from(now.plus(validityAmount, validityUnit).toInstant());

        ContentSigner contentSigner = new JcaContentSignerBuilder(signingAlgorithm)
            .build(issuerKey);
        X509CertificateHolder holder;
        switch (version) {
            case CertificateVersion.V1:
                holder = new JcaX509v1CertificateBuilder(
                        ISSUER, serialNumber, notBefore, notAfter, SUBJECT, subjectKey)
                    .build(contentSigner);
                break;

            case CertificateVersion.V3:
                holder = new JcaX509v3CertificateBuilder(
                        ISSUER, serialNumber, notBefore, notAfter, SUBJECT, subjectKey)
                    .build(contentSigner);
                break;

            default:
                throw new IllegalArgumentException("Unsupported version " + version);
        }
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    @Override
    public String encodeToPEM(Object obj) throws Exception {
        StringWriter str = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(str)) {
            pemWriter.writeObject(obj);
        }
        str.close();
        return str.toString();
    }

    @Override
    public PrivateKey decodePrivateKeyPEM(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            return KEY_CONVERTER.getPrivateKey((PrivateKeyInfo) parser.readObject());
        }
    }

    @Override
    public PublicKey decodePublicKeyPEM(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            return KEY_CONVERTER.getPublicKey((SubjectPublicKeyInfo) parser.readObject());
        }
    }

}
