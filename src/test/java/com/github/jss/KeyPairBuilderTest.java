package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.XECKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.interfaces.DHKey;
import javax.crypto.spec.DHParameterSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

public class KeyPairBuilderTest {

    @Test
    public void testDefault() throws Exception {
        KeyPair keyPair = KeyPairBuilder.defaultKeyPair();

        assertAll(
            () -> assertEquals(Defaults.getKeyAlgorithm(), keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals(Defaults.getKeyAlgorithm(), keyPair.getPublic().getAlgorithm()),
            () -> assertEquals(Defaults.getKeySize(), getSize(keyPair.getPrivate())),
            () -> assertEquals(Defaults.getKeySize(), getSize(keyPair.getPublic()))
        );
    }

    @ParameterizedTest
    @CsvSource({
        "DH,          512, javax.crypto.interfaces.DHKey",
        "DSA,        1024, java.security.interfaces.DSAKey",
        "EC,          384, java.security.interfaces.ECKey",
        "EdDSA,       255, java.security.interfaces.EdECKey",
        "EdDSA,       448, java.security.interfaces.EdECKey",
        "RSA,        4096, java.security.interfaces.RSAKey",
        "RSASSA-PSS, 3072, java.security.interfaces.RSAKey",
        "XDH,         255, java.security.interfaces.XECKey",
        "XDH,         448, java.security.interfaces.XECKey"
    })
    public void testWithSize(String algorithm, int keySize, Class<? extends Key> keyClass)
            throws Exception {
        KeyPairBuilder builder = new KeyPairBuilder()
            .withAlgorithm(algorithm)
            .withSize(keySize);
        KeyPair keyPair = builder.build();

        assertAll(
            () -> assertTrue(keyClass.isInstance(keyPair.getPrivate())),
            () -> assertTrue(keyClass.isInstance(keyPair.getPublic())),
            () -> assertEquals(builder.algorithm, keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals(builder.algorithm, keyPair.getPublic().getAlgorithm()),
            () -> assertEquals(builder.size, getSize(keyPair.getPrivate())),
            () -> assertEquals(builder.size, getSize(keyPair.getPublic()))
        );
    }

    @EnabledForJreRange(minVersion = 24)
    @ParameterizedTest
    @CsvSource({
        "ML-DSA,       ML-DSA-65,	sun.security.pkcs.NamedPKCS8Key, sun.security.x509.NamedX509Key",
        "ML-DSA-44,    ML-DSA-44,	sun.security.pkcs.NamedPKCS8Key, sun.security.x509.NamedX509Key",
        "ML-DSA-65,    ML-DSA-65,	sun.security.pkcs.NamedPKCS8Key, sun.security.x509.NamedX509Key",
        "ML-DSA-87,    ML-DSA-87,	sun.security.pkcs.NamedPKCS8Key, sun.security.x509.NamedX509Key",
        "ML-KEM,       ML-KEM-768,	sun.security.pkcs.NamedPKCS8Key, sun.security.x509.NamedX509Key",
        "ML-KEM-512,   ML-KEM-512,	sun.security.pkcs.NamedPKCS8Key, sun.security.x509.NamedX509Key",
        "ML-KEM-768,   ML-KEM-768,	sun.security.pkcs.NamedPKCS8Key, sun.security.x509.NamedX509Key",
        "ML-KEM-1024,  ML-KEM-1024,	sun.security.pkcs.NamedPKCS8Key, sun.security.x509.NamedX509Key"
    })
    public void testWithNamedAlgorithm(String algorithm, String parameter,
            Class<? extends PrivateKey> privateKeyClass, Class<? extends PublicKey> publicKeyClass)
                    throws Exception {
        KeyPairBuilder builder = new KeyPairBuilder()
            .withAlgorithm(algorithm);
        KeyPair keyPair = builder.build();

        assertAll(
            () -> assertTrue(privateKeyClass.isAssignableFrom(keyPair.getPrivate().getClass())),
            () -> assertTrue(publicKeyClass.isAssignableFrom(keyPair.getPublic().getClass())),
            () -> assertEquals(builder.algorithm.substring(0, 6), keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals(builder.algorithm.substring(0, 6), keyPair.getPublic().getAlgorithm()),
            () -> assertEquals(parameter, ((NamedParameterSpec) keyPair.getPrivate().getParams()).getName()),
            () -> assertEquals(parameter, ((NamedParameterSpec) keyPair.getPublic().getParams()).getName())
        );
    }

    @ParameterizedTest
    @CsvSource({
        "00:f6:e0:49:11:22:3f:1f:d3:dc:ff:07:2e:5b:00:bc:1c:67:3b:96:50:cd:7b:50:7c:5b:16:7e:d4:a8:f0:df:c2:36:0b:ab:8d:79:e3:5a:93:12:9d:4f:b2:46:b7:58:b6:13:13:9f:f6:38:36:8c:6a:e2:44:d3:3b:20:05:02:c3," +
        "2",

        "00:ef:6c:11:31:6c:70:84:93:a2:db:1e:bc:c1:f2:6f:97:43:2d:c2:55:9d:56:9e:ab:38:7b:ff:66:d5:63:e9:d8:3f:fa:62:c8:df:7b:86:b8:1d:e1:c3:1e:be:38:9b:d7:38:a3:69:43:1e:65:18:d3:4c:69:71:66:b7:13:68:ad:a8:0b:80:02:63:7f:bf:c3:3b:2c:2e:e4:1a:3f:5a:33:97:3c:99:ec:a0:40:e4:6b:b0:1e:50:ae:e0:49:0a:47:5f:ad:7a:74:b2:be:a3:37:a7:13:3a:77:b9:3f:75:c7:df:7d:85:b2:9c:2e:b9:81:7b:b3:de:2a:da:a6:ab:f3," +
        "5",

        "00:e7:a0:6a:76:8d:f0:65:aa:a3:13:4f:1c:29:e2:af:5f:fe:cc:0a:b6:d1:cf:6a:ea:d3:4e:14:84:84:13:30:92:48:cf:8c:3f:5a:d1:fe:01:8c:7a:6f:a5:34:87:ad:ad:c2:51:84:d7:09:9a:52:e8:7d:2b:0a:d0:b5:e6:62:33:99:c4:d8:b9:15:7f:8d:34:e9:d2:24:bb:ad:39:14:a9:86:91:62:18:34:1c:70:36:3e:c8:95:5f:72:bd:bb:a9:32:c9:ca:84:7f:b9:42:20:ff:c7:df:6a:13:17:a4:d3:91:ed:f7:c8:79:bb:f9:c7:b4:15:6a:6c:b2:54:c7:61:00:be:be:99:f7:34:f7:91:0c:34:2b:7a:2b:9a:70:00:3f:9d:84:ed:58:a5:7a:7e:2c:21:a4:92:74:d8:61:07:9c:6b:50:0f:21:eb:53:77:e7:5e:bc:18:fa:1b:06:71:dd:a9:58:74:79:6e:90:6e:c6:58:55:c5:72:c0:58:ac:93:9d:6b:68:e9:f6:d8:b5:dd:e6:34:f6:f8:39:59:bf:35:00:93:ad:0c:32:02:8e:c4:70:d3:3a:c9:1a:44:97:cb:b6:c4:cb:60:eb:30:05:14:19:62:1a:20:51:47:a2:15:5b:2a:cd:dd:a9:b0:17:20:86:03:2d:7c:02:98:0b," +
        "2"
    })
    public void testWithParamsDH(@ConvertWith(HexConverter.class) BigInteger p,
            BigInteger g) throws Exception {
        KeyPair keyPair = new KeyPairBuilder()
            .withParams(new DHParameterSpec(p, g))
            .build();

        assertAll(
            () -> assertTrue(keyPair.getPrivate() instanceof DHKey),
            () -> assertTrue(keyPair.getPublic() instanceof DHKey),
            () -> assertEquals("DH", keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals("DH", keyPair.getPublic().getAlgorithm())
        );

        DHParameterSpec privateParams = ((DHKey) keyPair.getPrivate()).getParams();
        DHParameterSpec publicParams = ((DHKey) keyPair.getPublic()).getParams();
        assertAll(
            () -> assertEquals(p, privateParams.getP()),
            () -> assertEquals(g, privateParams.getG()),
            () -> assertEquals(p, publicParams.getP()),
            () -> assertEquals(g, publicParams.getG())
        );
    }

    @ParameterizedTest
    @CsvSource({
        "00:a9:69:7c:aa:7d:53:ca:a4:35:84:03:ff:d4:ae:44:8c:33:5c:50:64:51:a4:3a:3e:d9:6c:7e:43:21:c2:6f:5e:d3:02:b5:32:fc:d4:50:5b:c3:b6:b2:43:f6:72:e1:07:1d:fb:14:ce:87:6f:c7:20:68:14:e4:93:d5:cb:54:13," +
        "00:99:80:00:cd:2a:2c:db:d7:a8:2a:d8:c6:2d:a4:e1:a1:a7:30:ac:b9," +
        "10:19:e6:74:b4:bc:9d:06:c5:6a:36:0c:90:b5:23:6a:2f:ce:75:c3:4c:00:4f:09:90:44:a0:0f:44:25:0f:b6:2b:21:52:70:b8:19:e6:7b:02:7b:3b:cc:6b:90:1a:32:cb:4b:06:22:25:12:b6:f2:4e:e9:45:24:b2:c7:84:ad",

        "00:e0:6e:86:9e:09:7c:cd:15:a5:d7:a0:eb:71:1e:76:5a:3a:dc:ea:24:7b:a2:d5:68:f5:ce:61:0a:bc:96:ca:82:47:5f:c7:bc:a9:3c:84:88:56:1f:a6:94:2f:e5:4e:0d:ce:f8:fc:c6:7f:53:95:75:c5:ed:d6:79:0b:f2:74:ea:5d:7d:b5:c8:5b:e2:52:cc:07:d0:a2:71:45:6b:c9:4b:f2:7e:5e:56:1a:35:01:05:1c:f1:7a:87:5c:13:cf:98:e8:20:0a:bf:d4:c0:34:b2:a8:ec:4d:82:7f:c8:af:d2:d5:3f:85:72:2e:3a:ea:db:5f:93:c2:a4:f6:2b:87:fd," +
        "00:83:b3:3b:bb:92:1d:52:09:67:be:23:7f:26:45:1e:50:ae:ad:95:13," +
        "00:bb:75:f4:f3:cb:5a:8c:da:ff:e1:21:3a:d7:78:b0:75:8b:99:c4:a0:e2:a0:cd:20:2f:43:b1:13:a2:17:27:0b:5c:c4:dc:91:96:ff:36:b4:63:e6:3e:06:7d:69:b4:a6:09:ee:53:0c:83:91:c6:73:70:73:37:fb:29:7b:3a:b5:e4:ef:81:f4:fd:e6:aa:d0:e1:ea:48:b0:77:f5:0f:02:ae:13:84:4e:04:b9:73:2b:b2:62:e0:28:13:2b:19:11:a4:d5:1a:25:7a:fd:8a:7a:16:57:08:07:4d:94:75:e5:5e:30:31:e1:75:d3:78:2c:cb:a3:0b:9c:17:06:8f:02",

        "00:82:e6:af:5b:61:1a:a3:41:87:4f:f2:9c:14:b0:f1:f1:6a:58:ee:14:c4:73:52:d5:61:f8:79:b0:79:90:59:8a:ad:76:42:df:af:92:8d:14:c9:aa:c6:32:ec:de:01:ca:36:15:c6:98:80:5e:01:e6:43:3b:9b:e4:fc:34:83:8a:fa:c2:66:12:69:bd:67:6b:b2:05:62:f4:44:53:f0:5c:a2:31:7f:b2:53:25:9b:bf:16:cd:85:03:99:a9:c0:f7:27:b8:6a:5b:ee:1f:38:51:dd:cf:11:5c:7a:b3:68:a7:de:72:fb:f4:83:40:83:27:d3:4c:60:c7:7c:0a:d0:44:a0:1c:27:63:61:55:8a:2f:6e:0f:d3:7f:69:9c:74:e5:09:ab:a2:6c:89:26:ad:a1:54:7c:fc:54:fa:ca:8b:22:0c:6f:15:33:c0:1d:db:48:c8:ea:19:18:f3:a4:30:42:48:24:21:67:1e:19:19:de:7e:cb:d9:99:2e:78:c8:a4:74:58:21:ad:bb:85:72:6a:03:5a:ab:7b:1d:62:86:a2:1d:b8:cc:32:dd:64:da:e2:0c:e6:74:ae:27:ea:e0:76:ae:71:bc:95:e4:c1:81:73:f4:33:5d:cf:68:67:57:ea:41:99:54:fd:f0:ef:5c:3a:16:af:27:a5:6b:57:cd:2d," +
        "00:d2:c3:a4:c3:30:6f:2d:34:b0:5f:cf:cf:3f:48:a2:b2:f6:82:3f:48:24:49:56:50:94:03:66:f1:ce:d0:9d:e9," +
        "3a:06:60:28:4f:a5:c7:81:fd:67:78:df:c4:da:91:98:75:b0:b5:ee:18:5e:c2:11:14:83:df:00:04:70:41:60:93:e7:12:92:d7:08:55:ac:32:25:dd:76:49:41:0f:21:0f:e5:ed:7d:c5:2d:f5:01:62:f5:1e:e3:61:08:20:cc:c7:41:47:c2:95:39:02:f1:85:c7:35:6b:87:59:f4:7b:38:e0:92:40:89:14:dd:97:c7:6c:6d:27:c0:85:17:83:2a:d2:e4:1b:75:0e:4d:bd:16:bd:46:f2:c4:29:ab:f6:45:42:a2:53:5b:50:c4:e8:98:53:a3:fd:a0:f9:29:8b:87:9d:bb:16:74:db:66:8f:89:87:fa:f9:80:e2:35:97:b7:4b:31:56:33:37:4e:bb:66:c4:9c:4d:c8:0b:5e:a5:a3:8a:82:cc:55:b8:d6:59:cd:45:8a:fe:bd:fd:d3:38:86:26:31:3e:3c:8d:3d:71:81:f4:f9:06:77:81:eb:0b:f9:f9:7e:57:65:ab:b2:f8:1f:69:89:fd:c9:bb:b8:58:9c:86:bf:d9:6b:f3:81:7b:ca:7d:06:01:b6:cd:8b:7c:40:49:65:46:39:e2:9f:cb:38:aa:da:42:69:4e:fe:67:f1:34:be:c1:b1:79:70:6d:67:95:97:c0:3b:4e:99:7c",

        "00:cf:62:8e:61:d6:be:2e:bd:f6:5f:a2:77:c9:1c:12:b7:4f:73:59:4a:dd:ff:ce:7c:8a:da:de:e3:31:6b:8d:7d:5f:e6:a7:16:5b:e4:16:74:4b:5d:04:ab:59:d1:41:7e:52:62:ab:a6:ff:42:e6:c6:49:af:22:0b:22:10:cc:58:3f:82:b4:3a:83:46:79:11:c8:1e:21:69:13:82:2a:9f:58:18:23:86:9b:29:9b:ba:1c:24:cc:c6:46:a9:fd:06:2c:24:0c:64:3b:0b:78:f5:ad:05:39:bf:70:34:f4:93:c0:fd:6f:cc:87:89:62:65:97:81:7b:df:74:dc:1c:ce:a2:57:c1:17:12:3b:af:ea:72:69:84:56:0c:39:15:7f:51:80:cd:d6:91:1d:e7:29:3c:39:85:44:13:d3:7c:73:27:e1:39:f0:50:63:44:d3:c2:5c:03:f8:1b:4d:66:cc:cb:1c:46:2c:6c:de:cc:39:45:1c:00:f1:d8:75:5d:92:7e:db:1d:d2:fa:d4:39:fb:c1:24:1d:6a:9d:e9:be:2a:93:29:2a:3a:01:fb:59:43:c6:73:39:d5:c7:b3:cc:7c:4d:53:5e:55:1a:c0:af:45:b1:44:de:71:85:7f:7d:06:8f:d0:92:3d:59:8a:15:a1:30:08:23:1f:97:2f:35:f3:f6:46:e9:5c:27:28:28:da:40:e7:03:ca:71:7e:ad:ff:a7:c4:1c:93:2f:3c:1a:52:c5:0c:e7:d1:ea:01:8c:5f:4b:18:20:fd:fe:73:3b:be:b2:57:3c:c1:44:12:0b:2d:50:1b:98:8a:86:1b:36:69:ef:a1:21:b8:ef:6b:9e:72:a2:48:2b:c1:23:60:ee:c0:c2:92:69:bc:04:04:a0:bb:28:57:16:25:8f:9f:a9:37:a6:c2:ff:32:80:56:fa:70:d0:9f:3a:6d:5d:85:bf:a6:bd:e6:36:15:12:44:b1:20:f4:93:6c:e9:6a:a6:05:49:78:8c:5d:cd:ed:e6:9b:27," +
        "00:f8:1f:44:42:18:3e:b7:e8:f4:a9:59:80:07:61:82:dd:0f:7f:e7:34:38:84:42:00:ac:c6:9f:f0:46:b8:13:71," +
        "00:c7:ea:21:c5:72:38:6f:fd:49:95:8c:26:4b:83:f5:99:12:10:36:62:37:23:55:96:5c:71:05:55:17:c9:53:bb:2e:f9:fe:f0:65:1f:f4:9d:de:c5:29:79:b7:7d:c5:fc:95:19:b4:41:39:8a:ac:76:c5:2b:1d:37:a6:88:42:59:46:5f:e4:f7:be:f7:1f:f4:7d:ff:61:f5:50:04:a4:35:9f:7d:93:14:da:c8:9d:00:cf:ca:b1:00:eb:c0:6e:ce:9c:2f:62:a8:66:d1:54:ce:c9:11:66:b3:81:d4:64:7d:0f:4e:04:ba:1b:d4:a8:6e:8b:d5:31:47:6c:e4:69:c1:bb:74:96:eb:7b:ab:39:3d:1b:55:31:7c:fe:92:3b:57:ee:58:4b:b4:ac:f7:33:f0:de:39:ca:45:37:70:b7:f2:91:74:73:fe:aa:86:60:30:89:12:7d:64:24:63:5c:4e:e5:8f:a6:48:b8:47:62:7e:52:29:6c:73:76:aa:ca:25:3f:3f:7b:5b:c4:a9:f4:19:c2:81:74:df:22:d5:3d:fb:1c:24:68:ad:45:28:ac:96:af:87:39:16:99:3b:6f:eb:df:e8:39:e2:02:e7:8c:33:22:f0:48:f8:01:fd:3e:1e:ac:06:87:32:da:9a:1f:b5:16:8e:45:41:de:ed:97:70:15:4c:28:c8:de:ab:37:a1:54:a1:07:71:2e:47:61:ff:67:7e:28:b7:52:07:60:f8:a5:28:01:18:8c:e2:db:d8:c1:fa:8c:e1:d4:ed:03:10:7f:87:9a:7b:4c:90:25:f8:49:e2:a8:da:cb:3a:77:29:19:f4:cd:38:f8:07:8a:1c:63:82:f5:1c:80:ee:da:49:79:34:fc:8f:83:f9:6e:be:aa:e8:c7:72:e4:79:48:b5:66:33:2e:18:de:3b:6f:db:b4:10:5b:bb:b9:3b:a1:c2:65:19:c8:95:0a:4d:7c:05:20:49:b4:eb:db:a2:d6:1a:64:44:de:76:0e:da:6e:ca",
    })
    public void testWithParamsDSA(
            @ConvertWith(HexConverter.class) BigInteger p,
            @ConvertWith(HexConverter.class) BigInteger q,
            @ConvertWith(HexConverter.class) BigInteger g) throws Exception {
        KeyPair keyPair = new KeyPairBuilder()
            .withParams(new DSAParameterSpec(p, q, g))
            .build();

        assertAll(
            () -> assertTrue(keyPair.getPrivate() instanceof DSAKey),
            () -> assertTrue(keyPair.getPublic() instanceof DSAKey),
            () -> assertEquals("DSA", keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals("DSA", keyPair.getPublic().getAlgorithm())
        );

        DSAParams privateParams = ((DSAKey) keyPair.getPrivate()).getParams();
        DSAParams publicParams = ((DSAKey) keyPair.getPublic()).getParams();
        assertAll(
            () -> assertEquals(p, privateParams.getP()),
            () -> assertEquals(q, privateParams.getQ()),
            () -> assertEquals(g, privateParams.getG()),
            () -> assertEquals(p, publicParams.getP()),
            () -> assertEquals(q, publicParams.getQ()),
            () -> assertEquals(g, publicParams.getG())
        );
    }

    @ParameterizedTest
    @CsvSource({
        "secp256r1,    1.2.840.10045.3.1.7",
        "secp384r1,    1.3.132.0.34",
        "secp521r1,    1.3.132.0.35"
    })
    public void testWithParamsEC(String stdName,
            @ConvertWith(StdNameConverter.class) ECParameterSpec spec) throws Exception {
        KeyPair keyPair = new KeyPairBuilder()
            .withParams(new ECGenParameterSpec(stdName))
            .build();

        assertAll(
            () -> assertTrue(keyPair.getPrivate() instanceof ECKey),
            () -> assertTrue(keyPair.getPublic() instanceof ECKey),
            () -> assertEquals("EC", keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals("EC", keyPair.getPublic().getAlgorithm())
        );
        assertAll(
            () -> assertEquals(spec, ((ECKey) keyPair.getPrivate()).getParams()),
            () -> assertEquals(spec, ((ECKey) keyPair.getPublic()).getParams())
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "Ed25519",
        "Ed448"
    })
    public void testWithParamsEdDSA(String stdName) throws Exception {
        KeyPair keyPair = new KeyPairBuilder()
            .withParams(new NamedParameterSpec(stdName))
            .build();

        assertAll(
            () -> assertTrue(keyPair.getPrivate() instanceof EdECKey),
            () -> assertTrue(keyPair.getPublic() instanceof EdECKey),
            () -> assertEquals("EdDSA", keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals("EdDSA", keyPair.getPublic().getAlgorithm())
        );
        assertAll(
            () -> assertEquals(stdName, ((NamedParameterSpec)
                    ((EdECKey) keyPair.getPrivate()).getParams()).getName()),
            () -> assertEquals(stdName, ((NamedParameterSpec)
                    ((EdECKey) keyPair.getPublic()).getParams()).getName())
        );
    }

    @ParameterizedTest
    @CsvSource({
        " 512,  65537",
        " 768,   4097",
        "1024,    257",
        "2048,     17",
        "3072,      7",
        "4096,      3"
    })
    public void testWithParamsRSA(int keySize, BigInteger publicExponent)
            throws Exception {
        KeyPair keyPair = new KeyPairBuilder()
            .withParams(new RSAKeyGenParameterSpec(keySize, publicExponent))
            .build();

        assertAll(
            () -> assertTrue(keyPair.getPrivate() instanceof RSAKey),
            () -> assertTrue(keyPair.getPublic() instanceof RSAKey),
            () -> assertEquals("RSA", keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals("RSA", keyPair.getPublic().getAlgorithm()),
            () -> assertEquals(keySize, getSize(keyPair.getPrivate())),
            () -> assertEquals(keySize, getSize(keyPair.getPublic()))
        );
    }

    @ParameterizedTest
    @CsvSource({
        " 512,  65537",
        " 768,   4097",
        "1024,    257",
        "2048,     17",
        "3072,      7",
        "4096,      3"
    })
    public void testWithParamsRSASSA_PSS(int keySize, BigInteger publicExponent)
            throws Exception {
        KeyPair keyPair = new KeyPairBuilder()
            .withAlgorithm("RSASSA-PSS")
            .withParams(new RSAKeyGenParameterSpec(keySize, publicExponent))
            .build();

        assertAll(
            () -> assertTrue(keyPair.getPrivate() instanceof RSAKey),
            () -> assertTrue(keyPair.getPublic() instanceof RSAKey),
            () -> assertEquals("RSASSA-PSS", keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals("RSASSA-PSS", keyPair.getPublic().getAlgorithm()),
            () -> assertEquals(keySize, getSize(keyPair.getPrivate())),
            () -> assertEquals(keySize, getSize(keyPair.getPublic()))
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "X25519",
        "X448"
    })
    public void testWithParamsXDH(String stdName) throws Exception {
        KeyPair keyPair = new KeyPairBuilder()
            .withParams(new NamedParameterSpec(stdName))
            .build();

        assertAll(
            () -> assertTrue(keyPair.getPrivate() instanceof XECKey),
            () -> assertTrue(keyPair.getPublic() instanceof XECKey),
            () -> assertEquals("XDH", keyPair.getPrivate().getAlgorithm()),
            () -> assertEquals("XDH", keyPair.getPublic().getAlgorithm())
        );
        assertAll(
            () -> assertEquals(stdName, ((NamedParameterSpec)
                    ((XECKey) keyPair.getPrivate()).getParams()).getName()),
            () -> assertEquals(stdName, ((NamedParameterSpec)
                    ((XECKey) keyPair.getPublic()).getParams()).getName())
        );
    }

    protected static int getSize(Key key) {
        if (key instanceof DHKey) {
            return ((DHKey) key).getParams().getP().bitLength();
        }
        if (key instanceof DSAKey) {
            return ((DSAKey) key).getParams().getP().bitLength();
        }
        if (key instanceof ECKey) {
            return ((ECKey) key).getParams().getCurve().getA().bitLength();
        }
        if (key instanceof RSAKey) {
            return ((RSAKey) key).getModulus().bitLength();
        }

        NamedParameterSpec namedParameterSpec = null;
        if (key instanceof EdECKey) {
            namedParameterSpec = (NamedParameterSpec) ((EdECKey) key).getParams();
        }
        if (key instanceof XECKey) {
            namedParameterSpec = (NamedParameterSpec) ((XECKey) key).getParams();
        }
        if (namedParameterSpec != null) {
            switch (namedParameterSpec.getName()) {
                case "Ed25519":
                case "X25519":
                    return 255;
                case "Ed448":
                case "X448":
                    return 448;
            }
        }

        throw new IllegalArgumentException(key.getClass().getName());
    }

}
