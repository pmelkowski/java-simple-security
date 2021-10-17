package com.github.jss;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Encoder {

    public static String encode(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String encode(Certificate certificate) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    public static String getPEM(Key key) {
      String name = null;
      if (key instanceof PrivateKey) {
          name = "PRIVATE KEY";
      } else if (key instanceof PublicKey) {
          name = "PUBLIC KEY";
      }
      return getPEM(name, encode(key));
  }

    public static String getPEM(Certificate certificate) throws CertificateEncodingException {
        return getPEM("CERTIFICATE", encode(certificate));
    }

    protected static String getPEM(String name, String encoded) {
        return Stream.of(
                    Stream.of("-----BEGIN " + name + "-----"),
                    Stream.of(encoded.split("(?<=\\G.{64})")),
                    Stream.of("-----END " + name + "-----")
                ).flatMap(Function.identity())
            .collect(Collectors.joining("\n"));
    }

}
