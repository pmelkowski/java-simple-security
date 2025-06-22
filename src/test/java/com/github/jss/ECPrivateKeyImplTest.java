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

        "ec.secp384r1.private.pem," +
        "00:ce:d5:74:23:e0:1b:69:76:1d:31:b2:ca:80:97:13:2a:19:3a:64:88:ab:32:d3:e3:9a:90:82:e1:98:bb:94:1f:ef:e8:d0:02:e2:2d:9f:f4:b1:1d:a2:63:7b:14:61:0d," +
        "1.3.132.0.34",

        "ec.secp521r1.private.pem," +
        "01:cf:72:a9:e6:e4:e0:86:cc:81:09:2d:6c:92:48:9e:32:0c:70:21:4b:0f:70:a7:b7:0e:3b:a2:d9:32:b2:c3:91:03:4b:1d:1f:c9:63:34:61:59:15:2a:3a:9e:b9:e3:f3:a1:6c:75:42:7e:b3:f6:21:af:2c:55:61:a6:3d:49:cd:cf," +
        "1.3.132.0.35",

        "ec.sect571k1.private.pem," +
        "01:53:cf:20:28:54:3f:3a:13:56:f0:39:71:c1:e0:b6:9c:45:db:97:4b:6e:78:08:e1:7d:3a:8f:0f:f1:28:5f:e6:cb:0e:f1:80:63:0e:cb:b1:10:67:3d:4f:09:56:e0:db:d7:22:57:c8:1f:8c:ae:be:5b:d7:73:10:48:1b:31:be:05:ab:6d:9a:6f:ec:c2," +
        "1.3.132.0.38",

        "ec.sect571r1.private.pem," +
        "01:d8:d2:a8:7e:ee:f0:f9:cb:d2:c1:6e:f6:84:4e:af:7b:37:02:8f:d9:00:70:cb:76:14:1d:51:23:3f:a3:4a:32:3b:94:f0:97:eb:95:96:67:15:fc:20:14:7a:00:3f:64:2a:0e:fe:f2:6d:5c:1c:34:e3:b0:27:79:14:81:b0:78:4d:00:22:20:80:da:f2," +
        "1.3.132.0.39",

        "ec.c2tnb191v1.private.pem," +
        "1b:ee:1d:d7:db:b8:0e:27:86:2e:a6:9d:f3:91:f1:33:4b:4c:3e:e4:52:fb:11:3d," +
        "1.2.840.10045.3.0.5",

        "ec.c2tnb191v2.private.pem," +
        "14:7f:f1:1f:3b:b3:6d:5d:31:2e:11:f4:1c:ae:a4:c4:ee:3f:f6:ca:8d:30:a9:02," +
        "1.2.840.10045.3.0.6",

        "ec.c2tnb359v1.private.pem," +
        "00:e1:f6:28:70:ec:73:25:48:ed:52:05:40:74:8d:75:97:ff:eb:ba:0a:ee:3a:7e:88:d6:2f:35:45:4e:e4:7a:9b:f6:8c:44:b7:18:65:86:df:e2:dc:54:46," +
        "1.2.840.10045.3.0.18",

        "ec.c2tnb431r1.private.pem," +
        "02:d7:56:1a:28:76:1d:a2:c4:30:b6:0a:c8:f1:8d:fb:ab:d4:fa:c4:de:57:10:b9:92:77:29:ce:de:35:9c:56:b9:10:91:da:43:85:f2:fa:54:ef:0d:93:92:c9:36:d2:19:00:ec:c3:fd," +
        "1.2.840.10045.3.0.20",

        "ec.prime192v2.private.pem," +
        "2e:4a:b3:f6:fd:e1:62:e8:da:dd:f1:07:33:c5:c8:02:04:e7:80:3b:b7:0f:0a:60," +
        "1.2.840.10045.3.1.2",

        "ec.prime239v3.private.pem," +
        "70:2c:e3:bc:5d:8f:0c:cd:e2:af:eb:86:a3:f2:af:38:2c:9d:a1:8e:be:25:67:0f:2b:7f:b5:a1:98:de," +
        "1.2.840.10045.3.1.6",

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

    @ParameterizedTest
    @CsvSource({
        "secp112r1," +
        "d7:21:50:95:71:ce:43:64:df:f2:73:08:4d:46," +
        "1.3.132.0.6",

        "1.3.132.0.7," +
        "1d:3f:f1:20:7e:fc:2b:5a:ea:13:b0:c5:e7:6a," +
        "1.3.132.0.7",

        "secp384r1," +
        "00:ce:d5:74:23:e0:1b:69:76:1d:31:b2:ca:80:97:13:2a:19:3a:64:88:ab:32:d3:e3:9a:90:82:e1:98:bb:94:1f:ef:e8:d0:02:e2:2d:9f:f4:b1:1d:a2:63:7b:14:61:0d," +
        "1.3.132.0.34",

        "secp521r1," +
        "01:cf:72:a9:e6:e4:e0:86:cc:81:09:2d:6c:92:48:9e:32:0c:70:21:4b:0f:70:a7:b7:0e:3b:a2:d9:32:b2:c3:91:03:4b:1d:1f:c9:63:34:61:59:15:2a:3a:9e:b9:e3:f3:a1:6c:75:42:7e:b3:f6:21:af:2c:55:61:a6:3d:49:cd:cf," +
        "1.3.132.0.35",

        "NIST K-571," +
        "01:53:cf:20:28:54:3f:3a:13:56:f0:39:71:c1:e0:b6:9c:45:db:97:4b:6e:78:08:e1:7d:3a:8f:0f:f1:28:5f:e6:cb:0e:f1:80:63:0e:cb:b1:10:67:3d:4f:09:56:e0:db:d7:22:57:c8:1f:8c:ae:be:5b:d7:73:10:48:1b:31:be:05:ab:6d:9a:6f:ec:c2," +
        "1.3.132.0.38",

        "sect571r1," +
        "01:d8:d2:a8:7e:ee:f0:f9:cb:d2:c1:6e:f6:84:4e:af:7b:37:02:8f:d9:00:70:cb:76:14:1d:51:23:3f:a3:4a:32:3b:94:f0:97:eb:95:96:67:15:fc:20:14:7a:00:3f:64:2a:0e:fe:f2:6d:5c:1c:34:e3:b0:27:79:14:81:b0:78:4d:00:22:20:80:da:f2," +
        "1.3.132.0.39",

        "X9.62 c2tnb191v1," +
        "1b:ee:1d:d7:db:b8:0e:27:86:2e:a6:9d:f3:91:f1:33:4b:4c:3e:e4:52:fb:11:3d," +
        "1.2.840.10045.3.0.5",

        "1.2.840.10045.3.0.6," +
        "14:7f:f1:1f:3b:b3:6d:5d:31:2e:11:f4:1c:ae:a4:c4:ee:3f:f6:ca:8d:30:a9:02," +
        "1.2.840.10045.3.0.6",

        "X9.62 c2tnb359v1," +
        "00:e1:f6:28:70:ec:73:25:48:ed:52:05:40:74:8d:75:97:ff:eb:ba:0a:ee:3a:7e:88:d6:2f:35:45:4e:e4:7a:9b:f6:8c:44:b7:18:65:86:df:e2:dc:54:46," +
        "1.2.840.10045.3.0.18",

        "X9.62 c2tnb431r1," +
        "02:d7:56:1a:28:76:1d:a2:c4:30:b6:0a:c8:f1:8d:fb:ab:d4:fa:c4:de:57:10:b9:92:77:29:ce:de:35:9c:56:b9:10:91:da:43:85:f2:fa:54:ef:0d:93:92:c9:36:d2:19:00:ec:c3:fd," +
        "1.2.840.10045.3.0.20",

        "X9.62 prime192v2," +
        "2e:4a:b3:f6:fd:e1:62:e8:da:dd:f1:07:33:c5:c8:02:04:e7:80:3b:b7:0f:0a:60," +
        "1.2.840.10045.3.1.2",

        "X9.62 prime239v3," +
        "70:2c:e3:bc:5d:8f:0c:cd:e2:af:eb:86:a3:f2:af:38:2c:9d:a1:8e:be:25:67:0f:2b:7f:b5:a1:98:de," +
        "1.2.840.10045.3.1.6",

        "secp256r1," +
        "35:b9:38:6c:7f:16:93:83:24:3e:c9:98:95:a2:f5:da:9d:38:d5:2a:91:d8:9e:b4:c3:c6:b2:b5:19:b9:a2:12," +
        "1.2.840.10045.3.1.7"
    })
    public void testConstruct(
            String stdName,
            @ConvertWith(HexConverter.class) BigInteger s,
            String objectId) throws Exception {
        ECPrivateKey key = new ECPrivateKeyImpl(stdName, s);
        NamedCurve curve = (NamedCurve) key.getParams();

        assertAll(
            () -> assertEquals(s, key.getS()),
            () -> assertEquals(objectId, curve.getObjectId())
        );
    }

}
