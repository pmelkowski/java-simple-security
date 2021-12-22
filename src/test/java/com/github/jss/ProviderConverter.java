package com.github.jss;

import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.TypedArgumentConverter;
import com.github.jss.providers.BouncyCastle;
import com.github.jss.providers.Provider;
import com.github.jss.providers.Sun;

public class ProviderConverter extends TypedArgumentConverter<String, Provider> {

    private final static Provider SUN = new Sun();
    private final static Provider BC = new BouncyCastle();

    protected ProviderConverter() {
        super(String.class, Provider.class);
    }

    @Override
    protected Provider convert(String source) throws ArgumentConversionException {
        switch (source) {
            case "BC":
                return BC;
            case "SUN":
                return SUN;
            default:
                throw new ArgumentConversionException(source.toString());
        }
    }

}
