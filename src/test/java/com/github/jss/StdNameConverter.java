package com.github.jss;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.TypedArgumentConverter;

public class StdNameConverter extends TypedArgumentConverter<String, ECParameterSpec> {

    protected StdNameConverter() {
        super(String.class, ECParameterSpec.class);
    }

    @Override
    protected ECParameterSpec convert(String source) throws ArgumentConversionException {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(source));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
            throw new ArgumentConversionException(e.getMessage());
        }
    }

}
