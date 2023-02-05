package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERParameters;
import com.mi.car.jsse.easysec.util.Strings;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class SABERParameterSpec implements AlgorithmParameterSpec {
    public static final SABERParameterSpec firesaberkem128r3 = new SABERParameterSpec(SABERParameters.firesaberkem128r3);
    public static final SABERParameterSpec firesaberkem192r3 = new SABERParameterSpec(SABERParameters.firesaberkem192r3);
    public static final SABERParameterSpec firesaberkem256r3 = new SABERParameterSpec(SABERParameters.firesaberkem256r3);
    public static final SABERParameterSpec lightsaberkem128r3 = new SABERParameterSpec(SABERParameters.lightsaberkem128r3);
    public static final SABERParameterSpec lightsaberkem192r3 = new SABERParameterSpec(SABERParameters.lightsaberkem192r3);
    public static final SABERParameterSpec lightsaberkem256r3 = new SABERParameterSpec(SABERParameters.lightsaberkem256r3);
    private static Map parameters = new HashMap();
    public static final SABERParameterSpec saberkem128r3 = new SABERParameterSpec(SABERParameters.saberkem128r3);
    public static final SABERParameterSpec saberkem192r3 = new SABERParameterSpec(SABERParameters.saberkem192r3);
    public static final SABERParameterSpec saberkem256r3 = new SABERParameterSpec(SABERParameters.saberkem256r3);
    private final String name;

    private SABERParameterSpec(SABERParameters parameters2) {
        this.name = parameters2.getName();
    }

    public String getName() {
        return this.name;
    }

    public static SABERParameterSpec fromName(String name2) {
        return (SABERParameterSpec) parameters.get(Strings.toLowerCase(name2));
    }
}
