package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEParameters;
import com.mi.car.jsse.easysec.util.Strings;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class CMCEParameterSpec implements AlgorithmParameterSpec {
    public static final CMCEParameterSpec mceliece348864 = new CMCEParameterSpec(CMCEParameters.mceliece348864r3);
    public static final CMCEParameterSpec mceliece348864f = new CMCEParameterSpec(CMCEParameters.mceliece348864fr3);
    public static final CMCEParameterSpec mceliece460896 = new CMCEParameterSpec(CMCEParameters.mceliece460896r3);
    public static final CMCEParameterSpec mceliece460896f = new CMCEParameterSpec(CMCEParameters.mceliece460896fr3);
    public static final CMCEParameterSpec mceliece6688128 = new CMCEParameterSpec(CMCEParameters.mceliece6688128r3);
    public static final CMCEParameterSpec mceliece6688128f = new CMCEParameterSpec(CMCEParameters.mceliece6688128fr3);
    public static final CMCEParameterSpec mceliece6960119 = new CMCEParameterSpec(CMCEParameters.mceliece6960119r3);
    public static final CMCEParameterSpec mceliece6960119f = new CMCEParameterSpec(CMCEParameters.mceliece6960119fr3);
    public static final CMCEParameterSpec mceliece8192128 = new CMCEParameterSpec(CMCEParameters.mceliece8192128r3);
    public static final CMCEParameterSpec mceliece8192128f = new CMCEParameterSpec(CMCEParameters.mceliece8192128fr3);
    private static Map parameters = new HashMap();
    private final String name;

    private CMCEParameterSpec(CMCEParameters parameters2) {
        this.name = parameters2.getName();
    }

    public String getName() {
        return this.name;
    }

    public static CMCEParameterSpec fromName(String name2) {
        return (CMCEParameterSpec) parameters.get(Strings.toLowerCase(name2));
    }
}
