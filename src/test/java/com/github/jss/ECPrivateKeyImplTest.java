package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;
import sun.security.util.NamedCurve;

public class ECPrivateKeyImplTest {

    @ParameterizedTest
    @CsvSource({
        "ec.secp112r1.private.pem," +
        "d7:21:50:95:71:ce:43:64:df:f2:73:08:4d:46," +
        "1.3.132.0.6",

        "ec.secp112r2.private.pem," +
        "1d:3f:f1:20:7e:fc:2b:5a:ea:13:b0:c5:e7:6a," +
        "1.3.132.0.7",

        "ec.prime256v1.private.pem," +
        "35:b9:38:6c:7f:16:93:83:24:3e:c9:98:95:a2:f5:da:9d:38:d5:2a:91:d8:9e:b4:c3:c6:b2:b5:19:b9:a2:12," +
        "1.2.840.10045.3.1.7"
    })
    public void testConstruct(
            @ConvertWith(PEMConverter.class) byte[] encoded,
            @ConvertWith(HexConverter.class) BigInteger s,
            String objectId) throws Exception {
        ECPrivateKey key = new ECPrivateKeyImpl(encoded);
        NamedCurve curve = (NamedCurve) key.getParams();

        assertAll(
            () -> assertEquals(s, key.getS()),
            () -> assertEquals(objectId, curve.getObjectId())
        );
    }

}
