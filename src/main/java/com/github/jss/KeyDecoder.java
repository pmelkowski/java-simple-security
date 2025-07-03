package com.github.jss;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Optional;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

final class KeyDecoder {

    static {
        JavaBaseModule.addExports("sun.security.pkcs");
        JavaBaseModule.addExports("sun.security.util");
    }

    static Optional<String> decodeAlgorithm(byte[] encoded) {
        try {
            DerValue val = new DerValue(encoded);
            if (val.tag != DerValue.tag_Sequence) {
                return Optional.empty();
            }

            // algorithm or version (private keys only)
            DerValue derAlgorithm = val.data.getDerValue();
            if (derAlgorithm.tag == DerValue.tag_Integer) {
                // version, read next value
                derAlgorithm = val.data.getDerValue();
            }
            if (derAlgorithm.tag != DerValue.tag_Sequence) {
                return Optional.empty();
            }
            DerInputStream delAlgInStream = derAlgorithm.toDerInputStream();

            // algorithm.OID
            String oid = delAlgInStream.getOID().toString();

            // Use reflection for KnownOIDs added in JRE 11
            Class<?> knownOIDs = JavaBaseModule.getClass("sun.security.util.KnownOIDs");
            if (knownOIDs != null) {
                try {
                    Object found = knownOIDs.getMethod("findMatch", String.class).invoke(null, oid);
                    if (found == null) {
                        return Optional.empty();
                    }
                    return Optional.of(((String) knownOIDs.getMethod("stdName").invoke(found)).toUpperCase());
                } catch (SecurityException | IllegalAccessException | InvocationTargetException
                        | NoSuchMethodException e) {
                }
            }

            return Algorithms.findByOid(oid);
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    static Optional<PrivateKey> decodePrivateKey(String algorithm, byte[] encoded) {
        try {
            DerValue val = new DerValue(encoded);
            if (val.tag != DerValue.tag_Sequence) {
                return Optional.empty();
            }

            switch (algorithm) {
            case "DH":
            case "DIFFIEHELLMAN":
                return decodePrivateKeyDH(val);
            case "DSA":
                return decodePrivateKeyDSA(val);
            case "EC":
                return decodePrivateKeyEC(val);
            case "RSA":
                return decodePrivateKeyRSA(val);
            case "ML-DSA-44":
            case "ML-DSA-65":
            case "ML-DSA-87":
            case "ML-KEM-512":
            case "ML-KEM-768":
            case "ML-KEM-1024":
                return decodeNamedPrivateKey(algorithm, val);
            default:
                return Optional.empty();
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidParameterSpecException e) {
            return Optional.empty();
        }
    }

    static Optional<PublicKey> decodePublicKey(String algorithm, byte[] encoded) {
        try {
            DerValue val = new DerValue(encoded);
            if (val.tag != DerValue.tag_Sequence) {
                return Optional.empty();
            }

            switch (algorithm) {
            case "DH":
            case "DIFFIEHELLMAN":
                return decodePublicKeyDH(val);
            default:
                return Optional.empty();
            }
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    @SuppressWarnings("serial")
    private static Optional<PrivateKey> decodePrivateKeyDH(DerValue val) throws IOException {
        // version
        val.data.getBigInteger();

        // algorithm
        DerValue derAlgorithm = val.data.getDerValue();
        if (derAlgorithm.tag != DerValue.tag_Sequence) {
            return Optional.empty();
        }
        DerInputStream delAlgInStream = derAlgorithm.toDerInputStream();
        // algorithm.OID
        delAlgInStream.getOID();

        // algorithm.parameters
        DerValue derParams = delAlgInStream.getDerValue();
        if (derParams.tag != DerValue.tag_Sequence) {
            return Optional.empty();
        }
        derParams.data.reset();
        DHParameterSpec params = new DHParameterSpec(
                derParams.data.getBigInteger(),
                derParams.data.getBigInteger(),
                derParams.data.available() > 0 ? derParams.data.getBigInteger().intValue() : 0
        );

        // private key
        BigInteger x = new DerInputStream(val.data.getOctetString()).getBigInteger();

        return Optional.of(new DHPrivateKey() {
            @Override
            public String getAlgorithm() {
                return "DH";
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }

            @Override
            public BigInteger getX() {
                return x;
            }

            @Override
            public DHParameterSpec getParams() {
                return params;
            }
        });
    }

    @SuppressWarnings("serial")
    private static Optional<PrivateKey> decodePrivateKeyDSA(DerValue val) throws IOException {
        // version
        val.data.getBigInteger();

        DerValue next = val.data.getDerValue();
        if (next.tag == DerValue.tag_Sequence) {
            // Key with nested sequences is properly handled by the Sun Provider
            return Optional.empty();
        }

        // parameters
        BigInteger p = next.getBigInteger();
        BigInteger q = val.data.getBigInteger();
        BigInteger g = val.data.getBigInteger();

        // public key
        val.data.getBigInteger();

        // private key
        BigInteger x = val.data.getBigInteger();

        return Optional.of(new DSAPrivateKey() {
            @Override
            public String getAlgorithm() {
                return "DSA";
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }

            @Override
            public BigInteger getX() {
                return x;
            }

            @Override
            public DSAParams getParams() {
                return new DSAParams() {
                    @Override
                    public BigInteger getQ() {
                        return q;
                    }

                    @Override
                    public BigInteger getP() {
                        return p;
                    }

                    @Override
                    public BigInteger getG() {
                        return g;
                    }
                };
            }
        });
    }

    @SuppressWarnings("serial")
    private static Optional<PrivateKey> decodePrivateKeyEC(DerValue val)
            throws IOException, NoSuchAlgorithmException, InvalidParameterSpecException {
        // version
        val.data.getBigInteger();

        DerValue next = val.data.getDerValue();
        if (next.tag == DerValue.tag_Sequence) {
            // Key with nested sequences is properly handled by the Sun Provider
            return Optional.empty();
        }

        // private key
        BigInteger s = new DerValue(DerValue.tag_Integer, next.getOctetString()).getPositiveBigInteger();

        // algorithm name
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
        algParams.init(new ECGenParameterSpec(val.data.getDerValue().data.getOID().toString()));
        ECParameterSpec params = algParams.getParameterSpec(ECParameterSpec.class);

        // public key
        // der.data.getDerValue().data.getBitString();

        return Optional.of(new ECPrivateKey() {
            @Override
            public String getAlgorithm() {
                return "EC";
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }

            @Override
            public BigInteger getS() {
                return s;
            }

            @Override
            public ECParameterSpec getParams() {
                return params;
            }
        });
    }

    @SuppressWarnings("serial")
    private static Optional<PrivateKey> decodePrivateKeyRSA(DerValue val) throws IOException {
        // version
        val.data.getBigInteger();

        DerValue next = val.data.getDerValue();
        if (next.tag == DerValue.tag_Sequence) {
            // Key with nested sequences is properly handled by the Sun Provider
            return Optional.empty();
        }

        // parameters
        BigInteger n = next.getBigInteger();
        BigInteger e = val.data.getBigInteger();
        BigInteger d = val.data.getBigInteger();
        BigInteger p = val.data.getBigInteger();
        BigInteger q = val.data.getBigInteger();
        BigInteger pe = val.data.getBigInteger();
        BigInteger qe = val.data.getBigInteger();
        BigInteger coeff = val.data.getBigInteger();

        return Optional.of(new RSAPrivateCrtKey() {
            @Override
            public String getAlgorithm() {
                return "RSA";
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }

            @Override
            public BigInteger getModulus() {
                return n;
            }

            @Override
            public BigInteger getPublicExponent() {
                return e;
            }

            @Override
            public BigInteger getPrivateExponent() {
                return d;
            }

            @Override
            public BigInteger getPrimeP() {
                return p;
            }

            @Override
            public BigInteger getPrimeQ() {
                return q;
            }

            @Override
            public BigInteger getPrimeExponentP() {
                return pe;
            }

            @Override
            public BigInteger getPrimeExponentQ() {
                return qe;
            }

            @Override
            public BigInteger getCrtCoefficient() {
                return coeff;
            }
        });
    }

    private static Optional<PrivateKey> decodeNamedPrivateKey(String algorithm, DerValue val) throws IOException {
        // Use reflection for NamedPKCS8Key added in JRE 24
        Class<?> namedPKCS8Key = JavaBaseModule.getClass("sun.security.pkcs.NamedPKCS8Key");
        if (namedPKCS8Key == null) {
            return Optional.empty();
        }

        // version
        val.data.getBigInteger();

        // algorithm
        val.data.getDerValue();

        // key
        byte[] raw = val.data.getOctetString();
        if (raw[0] == DerValue.tag_OctetString) {
            // Key with nested octet strings is properly handled by the Sun Provider
            return Optional.empty();
        }

        try {
            return Optional.of((PrivateKey) namedPKCS8Key.getConstructor(String.class, String.class, byte[].class)
                    .newInstance(algorithm.substring(0, 6), algorithm, raw));
        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
                | NoSuchMethodException e) {
            return Optional.empty();
        }
    }

    @SuppressWarnings("serial")
    private static Optional<PublicKey> decodePublicKeyDH(DerValue val) throws IOException {
        // algorithm
        DerValue derAlgorithm = val.data.getDerValue();
        if (derAlgorithm.tag != DerValue.tag_Sequence) {
            return Optional.empty();
        }
        DerInputStream delAlgInStream = derAlgorithm.toDerInputStream();
        // algorithm.OID
        delAlgInStream.getOID();

        // algorithm.parameters
        DerValue derParams = delAlgInStream.getDerValue();
        if (derParams.tag != DerValue.tag_Sequence) {
            return Optional.empty();
        }
        derParams.data.reset();
        DHParameterSpec params = new DHParameterSpec(
                derParams.data.getBigInteger(),
                derParams.data.getBigInteger(),
                derParams.data.available() > 0 ? derParams.data.getBigInteger().intValue() : 0
        );

        // public key
        BigInteger y = new DerInputStream(val.data.getBitString()).getBigInteger();

        return Optional.of(new DHPublicKey() {
            @Override
            public String getAlgorithm() {
                return "DH";
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }

            @Override
            public BigInteger getY() {
                return y;
            }

            @Override
            public DHParameterSpec getParams() {
                return params;
            }
        });
    }

}
