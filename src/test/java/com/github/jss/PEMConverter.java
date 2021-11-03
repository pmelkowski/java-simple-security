package com.github.jss;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ArgumentConverter;

public class PEMConverter implements ArgumentConverter {

    private static final Pattern ENCODED_PATTERN = Pattern.compile(".*-+((?s).*?)-+.*");

    @SuppressWarnings("exports")
    @Override
    public Object convert(Object source, ParameterContext context)
            throws ArgumentConversionException {
        try {
            InputStream in = PEMConverter.class.getResourceAsStream(source.toString());
            String pem = new String(in.readAllBytes());
            Matcher matcher = ENCODED_PATTERN.matcher(pem);
            if (!matcher.find()) {
                throw new ArgumentConversionException("Invalid PEM file");
            }
            String encodedString = matcher.group(1).replaceAll("\\s", "");
            byte[] encoded = Base64.getDecoder().decode(encodedString);
 
            Class<?> type = context.getParameter().getType();
            if (byte[].class.equals(type)) {
                return encoded;
            } else if (InputStream.class.equals(type)) {
                return new ByteArrayInputStream(encoded);
            } else {
                throw new ArgumentConversionException(
                        "Invalid target type " + type.getName());
            }
        } catch (IOException e) {
            throw new ArgumentConversionException(e.getMessage());
        }
    }

}
