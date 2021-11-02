package com.github.jss;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;

public class DSAPrivateKeyImplTest {

    @ParameterizedTest
    @CsvSource({
        " 512," +
            "5f:8d:a7:15:bc:07:f4:ae:22:2c:d8:4f:b7:3f:e7:b7:87:b5:82:01," +
            "00:a9:69:7c:aa:7d:53:ca:a4:35:84:03:ff:d4:ae:44:8c:33:5c:50:64:51:a4:3a:3e:d9:6c:7e:43:21:c2:6f:5e:d3:02:b5:32:fc:d4:50:5b:c3:b6:b2:43:f6:72:e1:07:1d:fb:14:ce:87:6f:c7:20:68:14:e4:93:d5:cb:54:13," +
            "00:99:80:00:cd:2a:2c:db:d7:a8:2a:d8:c6:2d:a4:e1:a1:a7:30:ac:b9," +
            "10:19:e6:74:b4:bc:9d:06:c5:6a:36:0c:90:b5:23:6a:2f:ce:75:c3:4c:00:4f:09:90:44:a0:0f:44:25:0f:b6:2b:21:52:70:b8:19:e6:7b:02:7b:3b:cc:6b:90:1a:32:cb:4b:06:22:25:12:b6:f2:4e:e9:45:24:b2:c7:84:ad",

        "1024," +
            "19:57:0c:e8:9f:bb:d3:67:04:de:6c:74:ba:c7:34:bf:57:2e:ab:aa," +
            "00:e0:6e:86:9e:09:7c:cd:15:a5:d7:a0:eb:71:1e:76:5a:3a:dc:ea:24:7b:a2:d5:68:f5:ce:61:0a:bc:96:ca:82:47:5f:c7:bc:a9:3c:84:88:56:1f:a6:94:2f:e5:4e:0d:ce:f8:fc:c6:7f:53:95:75:c5:ed:d6:79:0b:f2:74:ea:5d:7d:b5:c8:5b:e2:52:cc:07:d0:a2:71:45:6b:c9:4b:f2:7e:5e:56:1a:35:01:05:1c:f1:7a:87:5c:13:cf:98:e8:20:0a:bf:d4:c0:34:b2:a8:ec:4d:82:7f:c8:af:d2:d5:3f:85:72:2e:3a:ea:db:5f:93:c2:a4:f6:2b:87:fd," +
            "00:83:b3:3b:bb:92:1d:52:09:67:be:23:7f:26:45:1e:50:ae:ad:95:13," +
            "00:bb:75:f4:f3:cb:5a:8c:da:ff:e1:21:3a:d7:78:b0:75:8b:99:c4:a0:e2:a0:cd:20:2f:43:b1:13:a2:17:27:0b:5c:c4:dc:91:96:ff:36:b4:63:e6:3e:06:7d:69:b4:a6:09:ee:53:0c:83:91:c6:73:70:73:37:fb:29:7b:3a:b5:e4:ef:81:f4:fd:e6:aa:d0:e1:ea:48:b0:77:f5:0f:02:ae:13:84:4e:04:b9:73:2b:b2:62:e0:28:13:2b:19:11:a4:d5:1a:25:7a:fd:8a:7a:16:57:08:07:4d:94:75:e5:5e:30:31:e1:75:d3:78:2c:cb:a3:0b:9c:17:06:8f:02",

        "2048," +
            "00:c0:99:0c:ef:b1:ca:32:79:3c:5f:25:74:ad:9b:c3:e9:2e:fa:6c:5a:ec:40:39:cb:06:d3:cc:9f:65:97:c4:da," +
            "00:82:e6:af:5b:61:1a:a3:41:87:4f:f2:9c:14:b0:f1:f1:6a:58:ee:14:c4:73:52:d5:61:f8:79:b0:79:90:59:8a:ad:76:42:df:af:92:8d:14:c9:aa:c6:32:ec:de:01:ca:36:15:c6:98:80:5e:01:e6:43:3b:9b:e4:fc:34:83:8a:fa:c2:66:12:69:bd:67:6b:b2:05:62:f4:44:53:f0:5c:a2:31:7f:b2:53:25:9b:bf:16:cd:85:03:99:a9:c0:f7:27:b8:6a:5b:ee:1f:38:51:dd:cf:11:5c:7a:b3:68:a7:de:72:fb:f4:83:40:83:27:d3:4c:60:c7:7c:0a:d0:44:a0:1c:27:63:61:55:8a:2f:6e:0f:d3:7f:69:9c:74:e5:09:ab:a2:6c:89:26:ad:a1:54:7c:fc:54:fa:ca:8b:22:0c:6f:15:33:c0:1d:db:48:c8:ea:19:18:f3:a4:30:42:48:24:21:67:1e:19:19:de:7e:cb:d9:99:2e:78:c8:a4:74:58:21:ad:bb:85:72:6a:03:5a:ab:7b:1d:62:86:a2:1d:b8:cc:32:dd:64:da:e2:0c:e6:74:ae:27:ea:e0:76:ae:71:bc:95:e4:c1:81:73:f4:33:5d:cf:68:67:57:ea:41:99:54:fd:f0:ef:5c:3a:16:af:27:a5:6b:57:cd:2d," +
            "00:d2:c3:a4:c3:30:6f:2d:34:b0:5f:cf:cf:3f:48:a2:b2:f6:82:3f:48:24:49:56:50:94:03:66:f1:ce:d0:9d:e9," +
            "3a:06:60:28:4f:a5:c7:81:fd:67:78:df:c4:da:91:98:75:b0:b5:ee:18:5e:c2:11:14:83:df:00:04:70:41:60:93:e7:12:92:d7:08:55:ac:32:25:dd:76:49:41:0f:21:0f:e5:ed:7d:c5:2d:f5:01:62:f5:1e:e3:61:08:20:cc:c7:41:47:c2:95:39:02:f1:85:c7:35:6b:87:59:f4:7b:38:e0:92:40:89:14:dd:97:c7:6c:6d:27:c0:85:17:83:2a:d2:e4:1b:75:0e:4d:bd:16:bd:46:f2:c4:29:ab:f6:45:42:a2:53:5b:50:c4:e8:98:53:a3:fd:a0:f9:29:8b:87:9d:bb:16:74:db:66:8f:89:87:fa:f9:80:e2:35:97:b7:4b:31:56:33:37:4e:bb:66:c4:9c:4d:c8:0b:5e:a5:a3:8a:82:cc:55:b8:d6:59:cd:45:8a:fe:bd:fd:d3:38:86:26:31:3e:3c:8d:3d:71:81:f4:f9:06:77:81:eb:0b:f9:f9:7e:57:65:ab:b2:f8:1f:69:89:fd:c9:bb:b8:58:9c:86:bf:d9:6b:f3:81:7b:ca:7d:06:01:b6:cd:8b:7c:40:49:65:46:39:e2:9f:cb:38:aa:da:42:69:4e:fe:67:f1:34:be:c1:b1:79:70:6d:67:95:97:c0:3b:4e:99:7c",

        "3072," +
            "00:a4:bc:f3:72:03:23:08:1f:22:55:1f:ae:cf:c2:64:ba:0a:1d:10:5f:36:31:28:e5:4e:29:ab:21:5e:d8:61:8c," +
            "00:cf:62:8e:61:d6:be:2e:bd:f6:5f:a2:77:c9:1c:12:b7:4f:73:59:4a:dd:ff:ce:7c:8a:da:de:e3:31:6b:8d:7d:5f:e6:a7:16:5b:e4:16:74:4b:5d:04:ab:59:d1:41:7e:52:62:ab:a6:ff:42:e6:c6:49:af:22:0b:22:10:cc:58:3f:82:b4:3a:83:46:79:11:c8:1e:21:69:13:82:2a:9f:58:18:23:86:9b:29:9b:ba:1c:24:cc:c6:46:a9:fd:06:2c:24:0c:64:3b:0b:78:f5:ad:05:39:bf:70:34:f4:93:c0:fd:6f:cc:87:89:62:65:97:81:7b:df:74:dc:1c:ce:a2:57:c1:17:12:3b:af:ea:72:69:84:56:0c:39:15:7f:51:80:cd:d6:91:1d:e7:29:3c:39:85:44:13:d3:7c:73:27:e1:39:f0:50:63:44:d3:c2:5c:03:f8:1b:4d:66:cc:cb:1c:46:2c:6c:de:cc:39:45:1c:00:f1:d8:75:5d:92:7e:db:1d:d2:fa:d4:39:fb:c1:24:1d:6a:9d:e9:be:2a:93:29:2a:3a:01:fb:59:43:c6:73:39:d5:c7:b3:cc:7c:4d:53:5e:55:1a:c0:af:45:b1:44:de:71:85:7f:7d:06:8f:d0:92:3d:59:8a:15:a1:30:08:23:1f:97:2f:35:f3:f6:46:e9:5c:27:28:28:da:40:e7:03:ca:71:7e:ad:ff:a7:c4:1c:93:2f:3c:1a:52:c5:0c:e7:d1:ea:01:8c:5f:4b:18:20:fd:fe:73:3b:be:b2:57:3c:c1:44:12:0b:2d:50:1b:98:8a:86:1b:36:69:ef:a1:21:b8:ef:6b:9e:72:a2:48:2b:c1:23:60:ee:c0:c2:92:69:bc:04:04:a0:bb:28:57:16:25:8f:9f:a9:37:a6:c2:ff:32:80:56:fa:70:d0:9f:3a:6d:5d:85:bf:a6:bd:e6:36:15:12:44:b1:20:f4:93:6c:e9:6a:a6:05:49:78:8c:5d:cd:ed:e6:9b:27," +
            "00:f8:1f:44:42:18:3e:b7:e8:f4:a9:59:80:07:61:82:dd:0f:7f:e7:34:38:84:42:00:ac:c6:9f:f0:46:b8:13:71," +
            "00:c7:ea:21:c5:72:38:6f:fd:49:95:8c:26:4b:83:f5:99:12:10:36:62:37:23:55:96:5c:71:05:55:17:c9:53:bb:2e:f9:fe:f0:65:1f:f4:9d:de:c5:29:79:b7:7d:c5:fc:95:19:b4:41:39:8a:ac:76:c5:2b:1d:37:a6:88:42:59:46:5f:e4:f7:be:f7:1f:f4:7d:ff:61:f5:50:04:a4:35:9f:7d:93:14:da:c8:9d:00:cf:ca:b1:00:eb:c0:6e:ce:9c:2f:62:a8:66:d1:54:ce:c9:11:66:b3:81:d4:64:7d:0f:4e:04:ba:1b:d4:a8:6e:8b:d5:31:47:6c:e4:69:c1:bb:74:96:eb:7b:ab:39:3d:1b:55:31:7c:fe:92:3b:57:ee:58:4b:b4:ac:f7:33:f0:de:39:ca:45:37:70:b7:f2:91:74:73:fe:aa:86:60:30:89:12:7d:64:24:63:5c:4e:e5:8f:a6:48:b8:47:62:7e:52:29:6c:73:76:aa:ca:25:3f:3f:7b:5b:c4:a9:f4:19:c2:81:74:df:22:d5:3d:fb:1c:24:68:ad:45:28:ac:96:af:87:39:16:99:3b:6f:eb:df:e8:39:e2:02:e7:8c:33:22:f0:48:f8:01:fd:3e:1e:ac:06:87:32:da:9a:1f:b5:16:8e:45:41:de:ed:97:70:15:4c:28:c8:de:ab:37:a1:54:a1:07:71:2e:47:61:ff:67:7e:28:b7:52:07:60:f8:a5:28:01:18:8c:e2:db:d8:c1:fa:8c:e1:d4:ed:03:10:7f:87:9a:7b:4c:90:25:f8:49:e2:a8:da:cb:3a:77:29:19:f4:cd:38:f8:07:8a:1c:63:82:f5:1c:80:ee:da:49:79:34:fc:8f:83:f9:6e:be:aa:e8:c7:72:e4:79:48:b5:66:33:2e:18:de:3b:6f:db:b4:10:5b:bb:b9:3b:a1:c2:65:19:c8:95:0a:4d:7c:05:20:49:b4:eb:db:a2:d6:1a:64:44:de:76:0e:da:6e:ca",

        "4096," +
            "00:ba:08:4f:d9:77:4c:b8:ef:7e:6b:0b:aa:fc:79:dd:65:62:e6:cd:6c:7b:20:30:65:76:98:32:9a:7a:11:f0:17," +
            "00:a8:81:a8:5f:b7:b9:f1:5f:17:ea:d5:3d:81:35:d2:2c:0a:e5:93:ad:c2:e9:da:23:fd:a1:40:57:50:72:aa:6c:3d:d9:79:ba:3e:4e:2d:8a:59:72:05:42:b8:ca:4c:20:36:29:ec:26:c6:97:74:15:8e:93:cc:bc:52:eb:7f:dc:ed:54:dd:3f:4a:3d:d8:06:68:70:b5:14:48:39:69:97:f5:73:74:96:8a:29:4f:8a:04:6e:06:b1:90:e1:d4:94:f9:d8:ce:1b:c6:36:42:e5:54:d3:41:5f:4c:f5:55:09:95:7c:e0:ab:d1:22:24:d9:f3:94:fd:36:b8:f6:3e:6a:04:f8:83:af:6f:2d:5e:03:dd:6e:5b:dd:f2:60:41:2b:64:7a:22:c6:e0:2b:df:0c:b6:5e:50:8b:84:95:16:2b:b6:4c:22:b5:51:53:b7:51:32:23:f5:ef:c1:71:31:2d:16:8c:0e:f5:5d:46:ac:73:7e:d6:b2:45:bd:72:e4:94:a0:19:de:03:11:49:3b:66:91:67:f7:7b:13:4b:48:5f:04:e2:12:a9:fc:92:09:0d:a4:50:62:2d:25:61:75:b8:ed:50:c8:77:ce:6d:1e:32:31:c9:ed:4e:82:84:57:95:23:db:1c:bd:34:fe:fd:77:10:a6:7d:bf:3b:03:ea:dc:7d:77:07:07:c1:c9:c8:c1:3b:16:bd:1e:7a:b6:1e:73:49:9d:a4:ee:b5:cc:09:a8:a6:ad:eb:73:0a:4b:ab:32:85:09:e5:c9:59:a2:36:dc:6c:49:92:f7:21:ed:6f:ae:b6:ea:57:56:66:02:db:37:31:76:55:70:13:da:9a:86:08:2a:bc:17:ee:b7:12:f3:3d:df:a5:2f:9d:68:43:ef:a7:8b:f7:cc:5f:5d:b4:24:37:3a:cc:14:e3:1d:b8:5c:e7:0f:aa:e5:d4:e7:aa:f5:9a:24:44:ee:c3:9e:6d:1f:1a:b0:62:17:5d:b0:df:13:a2:24:94:23:1c:d5:0e:48:54:d5:ac:1c:3f:db:76:bd:bc:51:d6:84:0b:0d:d9:58:f1:52:f0:c4:8f:4a:ed:bc:6e:17:7b:d6:40:74:b9:28:cc:36:4e:f7:dd:e9:50:1a:bd:46:21:6b:3c:6f:17:26:48:9c:b4:6c:57:e2:cd:f3:03:9a:75:ee:6f:47:17:54:ab:c2:87:c1:d0:ae:87:d5:0c:a6:00:54:98:30:62:8e:c6:ae:8e:f4:be:be:8f:1e:5b:46:ed:fc:08:6c:b4:33:ab:86:84:35:65:bd:a3:4d:e4:ca:10:d0:3d:2c:ad:e1:87:ac:18:c4:16:61:2b:64:a2:68:b2:74:87:db:68:ad," + 
            "00:be:1d:4a:02:52:c0:49:b0:30:0f:a0:aa:78:54:10:b3:19:37:2a:a2:18:25:b8:cc:40:08:ab:bf:97:bf:33:a7," +
            "0d:dd:7c:44:71:61:3a:91:aa:c2:f1:ae:3f:ef:ef:ce:0c:e6:83:c7:12:23:44:f7:3c:59:7b:60:2f:62:50:5b:2d:2a:35:94:f9:55:f2:ce:ea:b6:f5:bc:17:31:e9:f9:b2:76:98:8b:f1:04:fe:7a:e2:da:30:05:3b:04:29:28:be:21:2b:78:14:78:0e:a8:d0:df:00:66:b2:1e:9b:54:71:f0:c2:3b:d6:3f:56:16:92:4f:65:61:b2:86:fb:71:de:ab:ba:b0:c5:9c:36:e7:b7:ec:14:f1:b3:44:21:3f:1b:98:6a:37:b0:6d:06:d5:78:16:c6:b6:f5:60:76:1b:6d:b2:c7:16:2f:fb:69:9a:83:50:a4:52:3f:78:62:3d:f9:8c:41:a5:9e:a8:fe:d5:c5:30:12:cb:22:b0:d1:7a:a5:83:69:24:19:f1:f1:75:82:69:4d:21:e0:f4:29:9f:79:9a:28:f9:e3:17:4c:80:bb:98:1c:42:43:b3:8b:ca:6f:34:08:0c:63:55:8c:ea:ec:a5:93:c9:f5:7e:0e:0c:ee:2e:e7:75:2c:44:b1:45:51:c0:a0:d2:d3:08:2c:5c:a0:8a:93:81:01:76:fc:fd:0a:95:06:26:31:f4:87:a6:60:20:2a:ac:fd:08:a3:bb:81:26:14:4f:53:98:fe:5e:f0:8d:e3:ff:e2:00:6f:9c:7e:5d:c9:92:5d:bb:96:61:d4:a4:44:32:b8:be:91:7c:34:2d:68:bc:c5:8d:c5:23:f1:83:3d:29:cb:6c:03:8c:0b:fa:c5:b7:3d:a6:9e:3a:a9:d2:0f:eb:d7:b5:40:db:6e:08:9a:14:5d:e8:49:d1:dc:b7:dd:54:7d:bb:6a:5e:81:a7:8a:17:4d:26:75:43:e4:e9:82:bf:88:ce:2a:37:a2:ad:1b:5d:ec:3f:d9:07:5b:7a:0f:12:45:34:ad:87:0f:6b:5f:9c:f2:70:23:59:9d:28:bb:2a:78:92:98:90:00:63:98:df:39:4a:b8:56:5c:c7:18:68:ef:a2:bc:92:c8:f1:28:03:10:1e:40:c6:b3:a8:fa:02:01:0c:3a:10:f8:31:c3:bf:07:85:5a:5e:5d:b0:4d:26:0b:03:dd:0b:d7:0b:e2:d7:e8:e2:c7:3c:23:0b:97:8d:b4:59:87:dc:07:cc:85:db:b0:db:30:bd:ec:ed:79:0f:dd:2c:2d:fa:e8:8f:29:f8:67:37:0b:c1:af:7c:ae:83:de:39:26:e8:70:68:bd:2f:fb:50:87:13:78:72:d7:69:f6:57:b6:b6:8d:42:7f:e0:3f:6f:b5:29:13:29:f9:5a:c2:99:7f:dc:8a:8b:d0:41:56:34:08:f1,"
    })
    public void testConstructFromEncoded(int keySize,
            @ConvertWith(HexConverter.class) BigInteger X,
            @ConvertWith(HexConverter.class) BigInteger P,
            @ConvertWith(HexConverter.class) BigInteger Q,
            @ConvertWith(HexConverter.class) BigInteger G) throws Exception {
        PEM pem = new PEM(new String(DSAPrivateKeyImplTest.class.getResourceAsStream(
                "dsa." + keySize + ".private.pem").readAllBytes()));
        DSAPrivateKey key = new DSAPrivateKeyImpl(pem.getEncoded());

        assertAll(
            () -> assertEquals(X, key.getX()),
            () -> assertEquals(P, key.getParams().getP()),
            () -> assertEquals(Q, key.getParams().getQ()),
            () -> assertEquals(G, key.getParams().getG())
        );
    }

}
