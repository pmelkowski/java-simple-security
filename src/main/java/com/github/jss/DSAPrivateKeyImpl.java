package com.github.jss;

import java.io.IOException;
import java.io.InputStream;
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

    public DSAPrivateKeyImpl(byte[] encoded) throws InvalidKeyException {
        decode(encoded);
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

    @Override
    public void decode(InputStream in) throws InvalidKeyException {
        try {
            DerValue der = new DerValue(in);
            if (der.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Invalid key format");
            }

            // version
            der.data.getInteger();
            // parameters
            setDSAParams(
                der.data.getBigInteger(),
                der.data.getBigInteger(),
                der.data.getBigInteger()
            );
            // public key
            der.data.getBigInteger();
            // private key
            setX(
                der.data.getBigInteger()
            );
        } catch (IOException e) {
            throw new InvalidKeyException(e);
        }
    }

}
