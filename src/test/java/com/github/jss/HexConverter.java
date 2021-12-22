package com.github.jss;

import java.math.BigInteger;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.TypedArgumentConverter;

public class HexConverter extends TypedArgumentConverter<String, BigInteger> {

    protected HexConverter() {
        super(String.class, BigInteger.class);
    }

    @Override
    protected BigInteger convert(String source) throws ArgumentConversionException {
        return new BigInteger(source.replace(":", ""), 16);
    }

}
