package com.github.jss;

import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ArgumentConverter;
import com.github.jss.providers.BouncyCastle;
import com.github.jss.providers.Provider;
import com.github.jss.providers.Sun;

public class ProviderConverter implements ArgumentConverter {

    private final static Provider SUN = new Sun();
    private final static Provider BC = new BouncyCastle();

    @SuppressWarnings("exports")
    @Override
    public Object convert(Object source, ParameterContext context)
            throws ArgumentConversionException {
        switch (source.toString()) {
            case "BC":
                return BC;
            case "SUN":
                return SUN;
            default:
                throw new ArgumentConversionException(source.toString());
        }
    }

}
