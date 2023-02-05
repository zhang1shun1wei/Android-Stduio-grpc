package com.mi.car.jsse.easysec.pqc.jcajce.spec;

import com.mi.car.jsse.easysec.util.Strings;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class SPHINCSPlusParameterSpec implements AlgorithmParameterSpec {
    private static Map parameters = new HashMap();
    public static final SPHINCSPlusParameterSpec sha256_128f = new SPHINCSPlusParameterSpec("sha256-128f-robust");
    public static final SPHINCSPlusParameterSpec sha256_128f_simple = new SPHINCSPlusParameterSpec("sha256-128s-simple");
    public static final SPHINCSPlusParameterSpec sha256_128s = new SPHINCSPlusParameterSpec("sha256-128s-robust");
    public static final SPHINCSPlusParameterSpec sha256_128s_simple = new SPHINCSPlusParameterSpec("sha256-128f-simple");
    public static final SPHINCSPlusParameterSpec sha256_192f = new SPHINCSPlusParameterSpec("sha256-192f-robust");
    public static final SPHINCSPlusParameterSpec sha256_192f_simple = new SPHINCSPlusParameterSpec("sha256-192f-simple");
    public static final SPHINCSPlusParameterSpec sha256_192s = new SPHINCSPlusParameterSpec("sha256-192s-robust");
    public static final SPHINCSPlusParameterSpec sha256_192s_simple = new SPHINCSPlusParameterSpec("sha256-192s-simple");
    public static final SPHINCSPlusParameterSpec sha256_256f = new SPHINCSPlusParameterSpec("sha256-256f-robust");
    public static final SPHINCSPlusParameterSpec sha256_256f_simple = new SPHINCSPlusParameterSpec("sha256-256f-simple");
    public static final SPHINCSPlusParameterSpec sha256_256s = new SPHINCSPlusParameterSpec("sha256-256s-robust");
    public static final SPHINCSPlusParameterSpec sha256_256s_simple = new SPHINCSPlusParameterSpec("sha256-256s-simple");
    public static final SPHINCSPlusParameterSpec shake256_128f = new SPHINCSPlusParameterSpec("shake256-128f-robust");
    public static final SPHINCSPlusParameterSpec shake256_128f_simple = new SPHINCSPlusParameterSpec("shake256-128f-simple");
    public static final SPHINCSPlusParameterSpec shake256_128s = new SPHINCSPlusParameterSpec("shake256-128s-robust");
    public static final SPHINCSPlusParameterSpec shake256_128s_simple = new SPHINCSPlusParameterSpec("shake256-128s-simple");
    public static final SPHINCSPlusParameterSpec shake256_192f = new SPHINCSPlusParameterSpec("shake256-192f-robust");
    public static final SPHINCSPlusParameterSpec shake256_192f_simple = new SPHINCSPlusParameterSpec("shake256-192f-simple");
    public static final SPHINCSPlusParameterSpec shake256_192s = new SPHINCSPlusParameterSpec("shake256-192s-robust");
    public static final SPHINCSPlusParameterSpec shake256_192s_simple = new SPHINCSPlusParameterSpec("shake256-192s-simple");
    public static final SPHINCSPlusParameterSpec shake256_256f = new SPHINCSPlusParameterSpec("shake256-256f-robust");
    public static final SPHINCSPlusParameterSpec shake256_256f_simple = new SPHINCSPlusParameterSpec("shake256-256f-simple");
    public static final SPHINCSPlusParameterSpec shake256_256s = new SPHINCSPlusParameterSpec("shake256-256s-robust");
    public static final SPHINCSPlusParameterSpec shake256_256s_simple = new SPHINCSPlusParameterSpec("shake256-256s-simple");
    private final String name;

    static {
        parameters.put(sha256_128f.getName(), sha256_128f);
        parameters.put(sha256_128s.getName(), sha256_128s);
        parameters.put(sha256_192f.getName(), sha256_192f);
        parameters.put(sha256_192s.getName(), sha256_192s);
        parameters.put(sha256_256f.getName(), sha256_256f);
        parameters.put(sha256_256s.getName(), sha256_256s);
        parameters.put(sha256_128f_simple.getName(), sha256_128f_simple);
        parameters.put(sha256_128s_simple.getName(), sha256_128s_simple);
        parameters.put(sha256_192f_simple.getName(), sha256_192f_simple);
        parameters.put(sha256_192s_simple.getName(), sha256_192s_simple);
        parameters.put(sha256_256f_simple.getName(), sha256_256f_simple);
        parameters.put(sha256_256s_simple.getName(), sha256_256s_simple);
        parameters.put(shake256_128f.getName(), shake256_128f);
        parameters.put(shake256_128s.getName(), shake256_128s);
        parameters.put(shake256_192f.getName(), shake256_192f);
        parameters.put(shake256_192s.getName(), shake256_192s);
        parameters.put(shake256_256f.getName(), shake256_256f);
        parameters.put(shake256_256s.getName(), shake256_256s);
        parameters.put(shake256_128f_simple.getName(), shake256_128f_simple);
        parameters.put(shake256_128s_simple.getName(), shake256_128s_simple);
        parameters.put(shake256_192f_simple.getName(), shake256_192f_simple);
        parameters.put(shake256_192s_simple.getName(), shake256_192s_simple);
        parameters.put(shake256_256f_simple.getName(), shake256_256f_simple);
        parameters.put(shake256_256s_simple.getName(), shake256_256s_simple);
    }

    private SPHINCSPlusParameterSpec(String name2) {
        this.name = name2;
    }

    public String getName() {
        return this.name;
    }

    public static SPHINCSPlusParameterSpec fromName(String name2) {
        return (SPHINCSPlusParameterSpec) parameters.get(Strings.toLowerCase(name2));
    }
}
