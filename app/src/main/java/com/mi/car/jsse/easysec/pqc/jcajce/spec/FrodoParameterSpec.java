package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoParameters;
import com.mi.car.jsse.easysec.util.Strings;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class FrodoParameterSpec implements AlgorithmParameterSpec {
    public static final FrodoParameterSpec frodokem19888r3 = new FrodoParameterSpec(FrodoParameters.frodokem19888r3);
    public static final FrodoParameterSpec frodokem19888shaker3 = new FrodoParameterSpec(FrodoParameters.frodokem19888shaker3);
    public static final FrodoParameterSpec frodokem31296r3 = new FrodoParameterSpec(FrodoParameters.frodokem31296r3);
    public static final FrodoParameterSpec frodokem31296shaker3 = new FrodoParameterSpec(FrodoParameters.frodokem31296shaker3);
    public static final FrodoParameterSpec frodokem43088r3 = new FrodoParameterSpec(FrodoParameters.frodokem43088r3);
    public static final FrodoParameterSpec frodokem43088shaker3 = new FrodoParameterSpec(FrodoParameters.frodokem43088shaker3);
    private static Map parameters = new HashMap();
    private final String name;

    private FrodoParameterSpec(FrodoParameters parameters2) {
        this.name = parameters2.getName();
    }

    public String getName() {
        return this.name;
    }

    public static FrodoParameterSpec fromName(String name2) {
        return (FrodoParameterSpec) parameters.get(Strings.toLowerCase(name2));
    }
}
