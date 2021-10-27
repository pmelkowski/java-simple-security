package com.github.jss;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

public class ECPrivateKeyImpl extends PKCS8Key implements ECPrivateKey {

    private ECParameterSpec params;
    private BigInteger s;

    public ECPrivateKeyImpl(byte[] encoded) throws InvalidKeyException {
        decode(encoded);
    }

    @Override
    public ECParameterSpec getParams() {
        return params;
    }

    private void setParams(ObjectIdentifier oid)
            throws InvalidParameterSpecException, NoSuchAlgorithmException {
        params = ECNamedCurve.getByOid(oid)
            .map(ECNamedCurve::getSpec)
            .orElseThrow(() -> new InvalidParameterSpecException(oid.toString()));

        AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
        algParams.init(params);
        algid = new AlgorithmId(AlgorithmId.EC_oid, algParams);
    }

    @Override
    public BigInteger getS() {
        return s;
    }

    private void setKey(byte[] key) throws IOException {
        this.key = key;
        s = new DerValue(DerValue.tag_Integer, key).getPositiveBigInteger();
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
            // private key
            setKey(
                der.data.getOctetString()
            );
            // algorithm
            setParams(
                der.data.getDerValue().data.getOID()
            );
            // public key
            der.data.getDerValue().data.getBitString();
        } catch (IOException | InvalidParameterSpecException | NoSuchAlgorithmException e) {
            throw new InvalidKeyException(e);
        }
    }

}
