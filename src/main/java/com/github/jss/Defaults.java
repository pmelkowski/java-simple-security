package com.github.jss;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.Properties;

public class Defaults {

    // key properties
    private static final String keyAlgorithm;
    private static final int keySize;
    // certificate properties
    private static final long certificateValidityAmount;
    private static final TemporalUnit certificateValidityUnit;
    private static final int certificateVersion;
    private static final String signingAlgorithm;

    static {
        Properties props = new Properties();
        try {
            props.load(Defaults.class.getResourceAsStream("jss-defaults.properties"));
        } catch (IOException e) {
            // the code below will throw an unchecked exception
        }
        keyAlgorithm = props.getProperty("keyAlgorithm");
        keySize = Integer.valueOf(props.getProperty("keySize"));
        certificateValidityAmount = Long.valueOf(props.getProperty("certificateValidityAmount"));
        certificateValidityUnit = ChronoUnit.valueOf(props.getProperty("certificateValidityUnit"));
        certificateVersion = Integer.valueOf(props.getProperty("certificateVersion"));
        signingAlgorithm = props.getProperty("signingAlgorithm");
    }

    public static String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public static int getKeySize() {
        return keySize;
    }

    public static long getCertificateValidityAmount() {
        return certificateValidityAmount;
    }

    public static TemporalUnit getCertificateValidityUnit() {
        return certificateValidityUnit;
    }

    public static int getCertificateVersion() {
        return certificateVersion;
    }

    public static String getSigningAlgorithm() {
        return signingAlgorithm;
    }

}
