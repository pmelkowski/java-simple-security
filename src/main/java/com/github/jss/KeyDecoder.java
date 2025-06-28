package com.github.jss;

import java.io.IOException;
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
import java.util.Map;
import java.util.Optional;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;
import sun.security.util.KnownOIDs;

final class KeyDecoder {

    static {
        JavaBaseModule.addExports("sun.security.util");
    }

    // DH is not registered and can not be found by KnownOIDs.findMatch()
    private static final Map<String, String> ALGORITHM_OIDS = Map.of(
            KnownOIDs.DSA.value(),      KnownOIDs.DSA.name(),
            KnownOIDs.EC.value(),       KnownOIDs.EC.name(),
            KnownOIDs.X942_DH.value(),  "DH",
            KnownOIDs.RSA.value(),      KnownOIDs.RSA.name(),
            KnownOIDs.X25519.value(),   KnownOIDs.X25519.name(),
            KnownOIDs.X448.value(),     KnownOIDs.X448.name()
    );

    static Optional<String> decodeAlgorithm(byte[] encoded) {
        DerValue val = null;
        try {
            val = new DerValue(encoded);
            if (val.tag != DerValue.tag_Sequence) {
                return Optional.empty();
            }

            // version (private keys only)
            val.data.getOptional(DerValue.tag_Integer);

            // algorithm
            DerValue derAlgorithm = val.data.getDerValue();
            if (derAlgorithm.tag != DerValue.tag_Sequence) {
                return Optional.empty();
            }
            DerInputStream delAlgInStream = derAlgorithm.toDerInputStream();

            // algorithm.OID
            return Optional.ofNullable(ALGORITHM_OIDS.get(delAlgInStream.getOID().toString()));
        } catch (IOException e) {
            return Optional.empty();
        } finally {
            if (val != null) {
                val.clear();
            }
        }
    }

    static Optional<PrivateKey> decodePrivateKey(String algorithm, byte[] encoded) {
        DerValue val = null;
        try {
            val = new DerValue(encoded);
            if (val.tag != DerValue.tag_Sequence) {
                return Optional.empty();
            }

            switch (algorithm) {
            case "DH":
                return decodePrivateKeyDH(val);
            case "DSA":
                return decodePrivateKeyDSA(val);
            case "EC":
                return decodePrivateKeyEC(val);
            case "RSA":
                return decodePrivateKeyRSA(val);
            default:
                return Optional.empty();
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidParameterSpecException e) {
            return Optional.empty();
        } finally {
            if (val != null) {
                val.clear();
            }
        }
    }

    static Optional<PublicKey> decodePublicKey(String algorithm, byte[] encoded) {
        DerValue val = null;
        try {
            val = new DerValue(encoded);
            if (val.tag != DerValue.tag_Sequence) {
                return Optional.empty();
            }

            switch (algorithm) {
            case "DH":
                return decodePublicKeyDH(val);
            default:
                return Optional.empty();
            }
        } catch (IOException e) {
            return Optional.empty();
        } finally {
            if (val != null) {
                val.clear();
            }
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
                return val.toByteArray();
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

        if (val.data.getOptional(DerValue.tag_Sequence).isPresent()) {
            // Key with nested sequences is properly handled by the Sun Provider
            return Optional.empty();
        }

        // parameters
        BigInteger p = val.data.getBigInteger();
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
                return val.toByteArray();
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

        if (val.data.getOptional(DerValue.tag_Sequence).isPresent()) {
            // Key with nested sequences is properly handled by the Sun Provider
            return Optional.empty();
        }

        // private key
        BigInteger s = new DerValue(DerValue.tag_Integer, val.data.getOctetString()).getPositiveBigInteger();

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
                return val.toByteArray();
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

        if (val.data.getOptional(DerValue.tag_Sequence).isPresent()) {
            // Key with nested sequences is properly handled by the Sun Provider
            return Optional.empty();
        }

        // parameters
        BigInteger n = val.data.getBigInteger();
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
                return val.toByteArray();
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
                return val.toByteArray();
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
