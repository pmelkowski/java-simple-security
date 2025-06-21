package com.github.jss.providers;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
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
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
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
        JcaPEMWriter pemWriter = new JcaPEMWriter(str);
        pemWriter.writeObject(obj);
        pemWriter.close();
        str.close();
        return str.toString();
    }

    @Override
    public PrivateKey decodePrivateKeyPEM(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
	        PrivateKeyInfo info = (PrivateKeyInfo) parser.readObject();
	        return new JcaPEMKeyConverter().getPrivateKey(info);
        }
    }

    @Override
    public PublicKey decodePublicKeyPEM(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
	        SubjectPublicKeyInfo info = (SubjectPublicKeyInfo) parser.readObject();
	        return new JcaPEMKeyConverter().getPublicKey(info);
        }
    }

    @Override
    public boolean equals(Key key1, Key key2) throws Exception {
        if ((key1 instanceof ECPrivateKey) && !(key1 instanceof BCECPrivateKey)) {
            key1 = new BCECPrivateKey((ECPrivateKey) key1, BouncyCastleProvider.CONFIGURATION);
        }
        if ((key2 instanceof ECPrivateKey) && !(key2 instanceof BCECPrivateKey)) {
            key2 = new BCECPrivateKey((ECPrivateKey) key2, BouncyCastleProvider.CONFIGURATION);
        }

        if ((key1 instanceof ECPublicKey) && !(key1 instanceof BCECPublicKey)) {
            key1 = new BCECPublicKey((ECPublicKey) key1, BouncyCastleProvider.CONFIGURATION);
        }
        if ((key2 instanceof ECPublicKey) && !(key2 instanceof BCECPublicKey)) {
            key2 = new BCECPublicKey((ECPublicKey) key2, BouncyCastleProvider.CONFIGURATION);
        }

        if ((key1 instanceof XECPrivateKey) && !(key1 instanceof XDHPrivateKey)) {
            key1 = decodePrivateKey("XDH", key1.getEncoded());
        }
        if ((key2 instanceof XECPrivateKey) && !(key2 instanceof XDHPrivateKey)) {
            key2 = decodePrivateKey("XDH", key2.getEncoded());
        }

        if ((key1 instanceof XECPublicKey) && !(key1 instanceof XDHPublicKey)) {
            key1 = decodePublicKey("XDH", key1.getEncoded());
        }
        if ((key2 instanceof XECPublicKey) && !(key2 instanceof XDHPublicKey)) {
            key2 = decodePublicKey("XDH", key2.getEncoded());
        }

        return super.equals(key1, key2);
    }

}
