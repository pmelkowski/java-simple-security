package com.github.jss;

import java.lang.reflect.InvocationTargetException;
import java.security.spec.AlgorithmParameterSpec;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.TypedArgumentConverter;

public class NamedParameterConverter extends TypedArgumentConverter<String, AlgorithmParameterSpec> {

    protected NamedParameterConverter() {
        super(String.class, AlgorithmParameterSpec.class);
    }

    @Override
    protected AlgorithmParameterSpec convert(String stdName) throws ArgumentConversionException {
        try {
            // Use reflection to compile on various JDK versions
            return (AlgorithmParameterSpec) JavaBaseModule.getClass("java.security.spec.NamedParameterSpec")
                .getConstructor(String.class)
                .newInstance(stdName);
        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
                | NoSuchMethodException | SecurityException e) {
            throw new ArgumentConversionException(e.getMessage());
        }
    }

}
