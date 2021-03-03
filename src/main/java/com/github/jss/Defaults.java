package com.github.jss;

import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import sun.security.x509.CertificateVersion;

public class Defaults {

    private static String keyAlgorithm = "RSA";
    private static int keySize = 2048;

    private static long validityAmount = 2;
    private static TemporalUnit validityUnit = ChronoUnit.YEARS;
    private static int certificateVersion = CertificateVersion.V3;
    private static String signingAlgorithm = "SHA256withRSA";

    public static String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public static void setKeyAlgorithm(String keyAlgorithm) {
        Defaults.keyAlgorithm = keyAlgorithm;
    }

    public static int getKeySize() {
        return keySize;
    }

    public static void setKeySize(int keySize) {
        Defaults.keySize = keySize;
    }

    public static long getValidityAmount() {
        return validityAmount;
    }

    public static void setValidityAmount(long validityAmount) {
        Defaults.validityAmount = validityAmount;
    }

    public static TemporalUnit getValidityUnit() {
        return validityUnit;
    }

    public static void setValidityUnit(TemporalUnit validityUnit) {
        Defaults.validityUnit = validityUnit;
    }

    public static int getCertificateVersion() {
        return certificateVersion;
    }

    public static void setCertificateVersion(int certificateVersion) {
        Defaults.certificateVersion = certificateVersion;
    }

    public static String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public static void setSigningAlgorithm(String signingAlgorithm) {
        Defaults.signingAlgorithm = signingAlgorithm;
    }

}
