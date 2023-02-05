package com.mi.car.jsse.easysec.jsse.provider;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

class JcaAlgorithmDecomposer implements AlgorithmDecomposer {
    static final JcaAlgorithmDecomposer INSTANCE_JCA = new JcaAlgorithmDecomposer();
    private static final Pattern PATTERN = Pattern.compile("with|and|(?<!padd)in", 2);

    JcaAlgorithmDecomposer() {
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.AlgorithmDecomposer
    public Set<String> decompose(String algorithm) {
        if (algorithm.indexOf(47) < 0) {
            return Collections.emptySet();
        }
        Set<String> result = new HashSet<>();
        String[] split = algorithm.split("/");
        for (String section : split) {
            if (section.length() > 0) {
                String[] split2 = PATTERN.split(section);
                for (String part : split2) {
                    if (part.length() > 0) {
                        result.add(part);
                    }
                }
            }
        }
        ensureBothIfEither(result, "SHA1", "SHA-1");
        ensureBothIfEither(result, "SHA224", "SHA-224");
        ensureBothIfEither(result, "SHA256", "SHA-256");
        ensureBothIfEither(result, "SHA384", "SHA-384");
        ensureBothIfEither(result, "SHA512", "SHA-512");
        return result;
    }

    private static void ensureBothIfEither(Set<String> elements, String a, String b) {
        boolean hasA = elements.contains(a);
        if (hasA ^ elements.contains(b)) {
            if (!hasA) {
                b = a;
            }
            elements.add(b);
        }
    }
}
