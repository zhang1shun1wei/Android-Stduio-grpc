package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.jsse.java.security.BCCryptoPrimitive;
import java.security.Key;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

abstract class AbstractAlgorithmConstraints implements BCAlgorithmConstraints {
    protected final AlgorithmDecomposer decomposer;

    AbstractAlgorithmConstraints(AlgorithmDecomposer decomposer2) {
        this.decomposer = decomposer2;
    }

    /* access modifiers changed from: protected */
    public void checkAlgorithmName(String algorithm) {
        if (!JsseUtils.isNameSpecified(algorithm)) {
            throw new IllegalArgumentException("No algorithm name specified");
        }
    }

    /* access modifiers changed from: protected */
    public void checkKey(Key key) {
        if (key == null) {
            throw new NullPointerException("'key' cannot be null");
        }
    }

    /* access modifiers changed from: protected */
    public void checkPrimitives(Set<BCCryptoPrimitive> primitives) {
        if (!isPrimitivesSpecified(primitives)) {
            throw new IllegalArgumentException("No cryptographic primitive specified");
        }
    }

    /* access modifiers changed from: protected */
    public boolean containsAnyPartIgnoreCase(Set<String> elements, String algorithm) {
        if (elements.isEmpty()) {
            return false;
        }
        if (containsIgnoreCase(elements, algorithm)) {
            return true;
        }
        if (this.decomposer == null) {
            return false;
        }
        for (String part : this.decomposer.decompose(algorithm)) {
            if (containsIgnoreCase(elements, part)) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean containsIgnoreCase(Set<String> elements, String s) {
        for (String element : elements) {
            if (element.equalsIgnoreCase(s)) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean isPrimitivesSpecified(Set<BCCryptoPrimitive> primitives) {
        return primitives != null && !primitives.isEmpty();
    }

    protected static Set<String> asUnmodifiableSet(String[] algorithms) {
        if (algorithms != null && algorithms.length > 0) {
            Set<String> result = asSet(algorithms);
            if (!result.isEmpty()) {
                return Collections.unmodifiableSet(result);
            }
        }
        return Collections.emptySet();
    }

    protected static Set<String> asSet(String[] algorithms) {
        Set<String> result = new HashSet<>();
        if (algorithms != null) {
            for (String algorithm : algorithms) {
                if (algorithm != null) {
                    result.add(algorithm);
                }
            }
        }
        return result;
    }
}
