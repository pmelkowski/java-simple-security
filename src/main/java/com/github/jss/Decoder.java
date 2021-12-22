package com.github.jss;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

public class Decoder {

    public static PrivateKey decodePrivateKey(String encodedString)
           throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        Optional<PEM> pem = PEM.of(PEM.Type.PRIVATE_KEY, encodedString);
        byte[] encoded = pem
            .map(PEM::getEncoded)
            .orElseGet(() -> Base64.getDecoder().decode(encodedString));

        if (pem.map(PEM::getAlgorithm).isPresent()) {
            String algorithm = pem.get().getAlgorithm();
            switch (algorithm) {
                case "DSA":
                    return new DSAPrivateKeyImpl(encoded);
                case "EC":
                    return new ECPrivateKeyImpl(encoded);
                default:
                    return decodePrivateKey(algorithm, encoded);
            }
        } else {
            return decodePrivateKey(encoded);
        }
    }

    public static PrivateKey decodePrivateKey(byte[] encoded) throws InvalidKeySpecException {
        for (String algorithm : Algorithms.getKeyAlgorithms()) {
            try {
                return decodePrivateKey(algorithm, encoded);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            }
        }
        throw new InvalidKeySpecException();
    }

    private static PrivateKey decodePrivateKey(String algorithm, byte[] encoded)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance(algorithm)
            .generatePrivate(new PKCS8EncodedKeySpec(encoded, algorithm));
    }

    public static PublicKey decodePublicKey(String encodedString)
            throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        Optional<PEM> pem = PEM.of(PEM.Type.PUBLIC_KEY, encodedString);
        byte[] encoded = pem
            .map(PEM::getEncoded)
            .orElseGet(() -> Base64.getDecoder().decode(encodedString));

        if (pem.map(PEM::getAlgorithm).isPresent()) {
            return decodePublicKey(pem.get().getAlgorithm(), encoded);
        } else {
            return decodePublicKey(encoded);
        }
    }

    public static PublicKey decodePublicKey(byte[] encoded) throws InvalidKeySpecException {
        for (String algorithm : Algorithms.getKeyAlgorithms()) {
            try {
                return decodePublicKey(algorithm, encoded);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            }
        }
        throw new InvalidKeySpecException();
    }

    private static PublicKey decodePublicKey(String algorithm, byte[] encoded)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance(algorithm)
            .generatePublic(new X509EncodedKeySpec(encoded, algorithm));
    }

    public static Certificate decodeCertificate(String encodedString) throws CertificateException {
        byte[] encoded = encodedString.getBytes();
        Optional<PEM> pem = PEM.of(PEM.Type.CERTIFICATE, encodedString);
        if (pem.isEmpty()) {
            encoded = Base64.getDecoder().decode(encoded);
        }
        return decodeCertificate(encoded);
    }

    public static Certificate decodeCertificate(byte[] encoded) throws CertificateException {
        for (String algorithm : Algorithms.getCertificateAlgorithms()) {
            try {
                return CertificateFactory.getInstance(algorithm)
                    .generateCertificate(new ByteArrayInputStream(encoded));
            } catch (CertificateException e) {
            }
        }
        throw new CertificateException();
    }

}
