package com.github.jss;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

public final class ECPrivateKeyImpl extends PKCS8Key implements ECPrivateKey {

    private ECParameterSpec params;
    private BigInteger s;

    public ECPrivateKeyImpl() {
    }

    public ECPrivateKeyImpl(byte[] input) throws InvalidKeyException {
        try {
            decode(new DerValue(input));
        } catch (IOException e) {
            throw new InvalidKeyException("Unable to decode key", e);
        }
    }

    public ECPrivateKeyImpl(String stdName, BigInteger s) throws InvalidKeyException {
        try {
            setStdName(stdName);
            setS(s);
        } catch (InvalidParameterSpecException | IOException | NoSuchAlgorithmException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public ECParameterSpec getParams() {
        return params;
    }

    @Override
    public BigInteger getS() {
        return s;
    }

    private void setS(BigInteger s) throws IOException {
        this.s = s;
        key = new DerValue(DerValue.tag_Integer, s.toByteArray()).toByteArray();
    }

    private void setKey(byte[] key) throws IOException {
        this.key = key;
        s = new DerValue(DerValue.tag_Integer, key).getPositiveBigInteger();
    }

    private void setStdName(String stdName)
            throws InvalidParameterSpecException, NoSuchAlgorithmException {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(stdName));
        this.params = params.getParameterSpec(ECParameterSpec.class);
        algid = new AlgorithmId(AlgorithmId.EC_oid, params);
    }

    private void decode(DerValue val) throws InvalidKeyException {
        try {
            if (val.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Invalid key format");
            }

            // version
            val.data.getInteger();
            // private key
            setKey(
                val.data.getOctetString()
            );
            // algorithm name
            setStdName(
                val.data.getDerValue().data.getOID().toString()
            );
            // public key
            // der.data.getDerValue().data.getBitString();
        } catch (IOException | InvalidParameterSpecException | NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Unable to decode key", e);
        } finally {
            if (val != null) {
                val.clear();
            }
        }
    }

}
