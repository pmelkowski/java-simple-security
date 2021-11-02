package com.github.jss;

import java.math.BigInteger;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ArgumentConverter;

public class HexConverter implements ArgumentConverter {

    @SuppressWarnings("exports")
    @Override
    public Object convert(Object source, ParameterContext context)
            throws ArgumentConversionException {
        return new BigInteger(source.toString().replace(":", ""), 16);
    }

}
