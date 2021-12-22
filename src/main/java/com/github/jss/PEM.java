package com.github.jss;

import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class PEM {

    public enum Type {
        CERTIFICATE,
        PRIVATE_KEY,
        PUBLIC_KEY;

        private final String name;

        private Type() {
            name = name().replace('_', ' ');
        }

        public String getName() {
            return name;
        }

        private static final Map<String, Type> NAMES = Stream.of(Type.values())
            .collect(Collectors.toMap(type -> type.getName(), Function.identity()));

        public static Type getByName(String name) {
            return NAMES.get(name);
        }
    }

    private static final Pattern PEM_PATTERN = Pattern.compile(
        "\\s*" +
        "-+BEGIN (?<header>[A-Z\\s]+)-+" +
        "(?<encoded>(?s).*?)" +
        "-+END (?<footer>[A-Z\\s]+)-+" +
        "\\s*", Pattern.MULTILINE);

    private static final Pattern HEADER_PATTERN = Pattern.compile(
        "((?<algorithm>[^\\s]+)\\s)?" +
        "(?<type>" + Type.NAMES.keySet().stream()
            .collect(Collectors.joining("|")) + ")");

    private final Type type;
    private final String algorithm;
    private final byte[] encoded;

    public PEM(Type type, byte[] encoded) {
        this(type, null, encoded);
    }

    public PEM(Type type, String algorithm, byte[] encoded) {
        this.type = type;
        this.algorithm = algorithm;
        this.encoded = encoded;
    }

    public PEM(String pem) {
        this(PEM_PATTERN.matcher(pem));
    }

    private PEM(Matcher matcher) {
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid format");
        }

        String header = matcher.group("header");
        String footer = matcher.group("footer");
        if (!header.equals(footer)) {
            throw new IllegalArgumentException("Malformed header or footer");
        }

        this.encoded = Base64.getDecoder().decode(
                matcher.group("encoded").replaceAll("\\s", ""));

        matcher = HEADER_PATTERN.matcher(header);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Unsupported type: " + header);
        }

        this.type = Type.getByName(matcher.group("type"));
        this.algorithm = matcher.group("algorithm");
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public Type getType() {
        return type;
    }

    public byte[] getEncoded() {
        return encoded;
    }

    @Override
    public String toString() {
        String header = (algorithm != null ? algorithm + " " : "") + type.getName();
        return Stream.of(
                    Stream.of("-----BEGIN " + header + "-----"),
                    Stream.of(Base64.getEncoder().encodeToString(encoded)
                        .split("(?<=\\G.{64})")),
                    Stream.of("-----END " + header + "-----")
                ).flatMap(Function.identity())
            .collect(Collectors.joining("\n"));
    }

    public static Optional<PEM> of(String string) {
        return Optional.of(string)
            .map(PEM_PATTERN::matcher)
            .filter(Matcher::matches)
            .map(PEM::new);
    }

    public static Optional<PEM> of(Type type, String string) {
        Optional<PEM> pem = of(string);
        if (pem.isPresent()) {
            Type pemType = pem.get().getType();
            if (!type.equals(pemType)) {
                throw new IllegalArgumentException("Invalid type: " + pemType.toString());
            }
        }
        return pem;
    }

}
