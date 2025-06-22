package com.github.jss;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerValue;
import sun.security.x509.AlgIdDSA;

public final class DSAPrivateKeyImpl extends PKCS8Key implements DSAPrivateKey {

    private BigInteger x;

    public DSAPrivateKeyImpl() {
    }

    public DSAPrivateKeyImpl(byte[] input) throws InvalidKeyException {
        try {
            decode(new DerValue(input));
        } catch (IOException e) {
            throw new InvalidKeyException("Unable to decode key", e);
        }
    }

    public DSAPrivateKeyImpl(BigInteger x, BigInteger p, BigInteger q, BigInteger g)
            throws InvalidKeyException {
        try {
            setX(x);
            setDSAParams(p, q, g);
        } catch (IOException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public DSAParams getParams() {
        return (DSAParams) algid;
    }

    private void setDSAParams(BigInteger p, BigInteger q, BigInteger g) {
        algid = new AlgIdDSA(p, q, g);
    }

    @Override
    public BigInteger getX() {
        return x;
    }

    private void setX(BigInteger x) throws IOException {
        this.x = x;
        key = new DerValue(DerValue.tag_Integer, x.toByteArray()).toByteArray();
    }

    private void decode(DerValue val) throws InvalidKeyException {
        try {
            if (val.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Invalid key format");
            }

            // version
            val.data.getInteger();
            // parameters
            setDSAParams(
                val.data.getBigInteger(),
                val.data.getBigInteger(),
                val.data.getBigInteger()
            );
            // public key
            val.data.getBigInteger();
            // private key
            setX(
                val.data.getBigInteger()
            );
        } catch (IOException e) {
            throw new InvalidKeyException("Unable to decode key", e);
        } finally {
            if (val != null) {
                val.clear();
            }
        }
    }

}
