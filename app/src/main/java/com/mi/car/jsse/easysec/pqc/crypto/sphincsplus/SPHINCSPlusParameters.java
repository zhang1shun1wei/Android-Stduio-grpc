package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Pack;
import java.util.HashMap;
import java.util.Map;

public class SPHINCSPlusParameters {
    private static final Map oidToParams = new HashMap();
    private static final Map paramsToOid = new HashMap();
    public static final SPHINCSPlusParameters sha256_128f = new SPHINCSPlusParameters("sha256-128f-robust", new SPHINCSPlusEngine.Sha256Engine(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha256_128f_simple = new SPHINCSPlusParameters("sha256-128f-simple", new SPHINCSPlusEngine.Sha256Engine(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha256_128s = new SPHINCSPlusParameters("sha256-128s-robust", new SPHINCSPlusEngine.Sha256Engine(true, 16, 16, 7, 12, 14, 63));
    public static final SPHINCSPlusParameters sha256_128s_simple = new SPHINCSPlusParameters("sha256-128s-simple", new SPHINCSPlusEngine.Sha256Engine(false, 16, 16, 7, 12, 14, 63));
    public static final SPHINCSPlusParameters sha256_192f = new SPHINCSPlusParameters("sha256-192f-robust", new SPHINCSPlusEngine.Sha256Engine(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha256_192f_simple = new SPHINCSPlusParameters("sha256-192f-simple", new SPHINCSPlusEngine.Sha256Engine(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha256_192s = new SPHINCSPlusParameters("sha256-192s-robust", new SPHINCSPlusEngine.Sha256Engine(true, 24, 16, 7, 14, 17, 63));
    public static final SPHINCSPlusParameters sha256_192s_simple = new SPHINCSPlusParameters("sha256-192s-simple", new SPHINCSPlusEngine.Sha256Engine(false, 24, 16, 7, 14, 17, 63));
    public static final SPHINCSPlusParameters sha256_256f = new SPHINCSPlusParameters("sha256-256f-robust", new SPHINCSPlusEngine.Sha256Engine(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha256_256f_simple = new SPHINCSPlusParameters("sha256-256f-simple", new SPHINCSPlusEngine.Sha256Engine(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha256_256s = new SPHINCSPlusParameters("sha256-256s-robust", new SPHINCSPlusEngine.Sha256Engine(true, 32, 16, 8, 14, 22, 64));
    public static final SPHINCSPlusParameters sha256_256s_simple = new SPHINCSPlusParameters("sha256-256s-simple", new SPHINCSPlusEngine.Sha256Engine(false, 32, 16, 8, 14, 22, 64));
    public static final SPHINCSPlusParameters shake256_128f = new SPHINCSPlusParameters("shake256-128f-robust", new SPHINCSPlusEngine.Shake256Engine(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake256_128f_simple = new SPHINCSPlusParameters("shake256-128f-simple", new SPHINCSPlusEngine.Shake256Engine(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake256_128s = new SPHINCSPlusParameters("shake256-128s-robust", new SPHINCSPlusEngine.Shake256Engine(true, 16, 16, 7, 12, 14, 63));
    public static final SPHINCSPlusParameters shake256_128s_simple = new SPHINCSPlusParameters("shake256-128s-simple", new SPHINCSPlusEngine.Shake256Engine(false, 16, 16, 7, 12, 14, 63));
    public static final SPHINCSPlusParameters shake256_192f = new SPHINCSPlusParameters("shake256-192f-robust", new SPHINCSPlusEngine.Shake256Engine(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake256_192f_simple = new SPHINCSPlusParameters("shake256-192f-simple", new SPHINCSPlusEngine.Shake256Engine(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake256_192s = new SPHINCSPlusParameters("shake256-192s-robust", new SPHINCSPlusEngine.Shake256Engine(true, 24, 16, 7, 14, 17, 63));
    public static final SPHINCSPlusParameters shake256_192s_simple = new SPHINCSPlusParameters("shake256-192s-simple", new SPHINCSPlusEngine.Shake256Engine(false, 24, 16, 7, 14, 17, 63));
    public static final SPHINCSPlusParameters shake256_256f = new SPHINCSPlusParameters("shake256-256f-robust", new SPHINCSPlusEngine.Shake256Engine(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake256_256f_simple = new SPHINCSPlusParameters("shake256-256f-simple", new SPHINCSPlusEngine.Shake256Engine(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake256_256s = new SPHINCSPlusParameters("shake256-256s-robust", new SPHINCSPlusEngine.Shake256Engine(true, 32, 16, 8, 14, 22, 64));
    public static final SPHINCSPlusParameters shake256_256s_simple = new SPHINCSPlusParameters("shake256-256s-simple", new SPHINCSPlusEngine.Shake256Engine(false, 32, 16, 8, 14, 22, 64));
    private static final Integer sphincsPlus_sha256_128f_robust = Integers.valueOf(65793);
    private static final Integer sphincsPlus_sha256_128f_simple = Integers.valueOf(66049);
    private static final Integer sphincsPlus_sha256_128s_robust = Integers.valueOf(65794);
    private static final Integer sphincsPlus_sha256_128s_simple = Integers.valueOf(66050);
    private static final Integer sphincsPlus_sha256_192f_robust = Integers.valueOf(65795);
    private static final Integer sphincsPlus_sha256_192f_simple = Integers.valueOf(66051);
    private static final Integer sphincsPlus_sha256_192s_robust = Integers.valueOf(65796);
    private static final Integer sphincsPlus_sha256_192s_simple = Integers.valueOf(66052);
    private static final Integer sphincsPlus_sha256_256f_robust = Integers.valueOf(65797);
    private static final Integer sphincsPlus_sha256_256f_simple = Integers.valueOf(66053);
    private static final Integer sphincsPlus_sha256_256s_robust = Integers.valueOf(65798);
    private static final Integer sphincsPlus_sha256_256s_simple = Integers.valueOf(66054);
    private static final Integer sphincsPlus_shake256_128f_robust = Integers.valueOf(131329);
    private static final Integer sphincsPlus_shake256_128f_simple = Integers.valueOf(131585);
    private static final Integer sphincsPlus_shake256_128s_robust = Integers.valueOf(131330);
    private static final Integer sphincsPlus_shake256_128s_simple = Integers.valueOf(131586);
    private static final Integer sphincsPlus_shake256_192f_robust = Integers.valueOf(131331);
    private static final Integer sphincsPlus_shake256_192f_simple = Integers.valueOf(131587);
    private static final Integer sphincsPlus_shake256_192s_robust = Integers.valueOf(131332);
    private static final Integer sphincsPlus_shake256_192s_simple = Integers.valueOf(131588);
    private static final Integer sphincsPlus_shake256_256f_robust = Integers.valueOf(131333);
    private static final Integer sphincsPlus_shake256_256f_simple = Integers.valueOf(131589);
    private static final Integer sphincsPlus_shake256_256s_robust = Integers.valueOf(131334);
    private static final Integer sphincsPlus_shake256_256s_simple = Integers.valueOf(131590);
    private final SPHINCSPlusEngine engine;
    private final String name;

    static {
        oidToParams.put(sphincsPlus_sha256_128f_robust, sha256_128f);
        oidToParams.put(sphincsPlus_sha256_128s_robust, sha256_128s);
        oidToParams.put(sphincsPlus_sha256_192f_robust, sha256_192f);
        oidToParams.put(sphincsPlus_sha256_192s_robust, sha256_192s);
        oidToParams.put(sphincsPlus_sha256_256f_robust, sha256_256f);
        oidToParams.put(sphincsPlus_sha256_256s_robust, sha256_256s);
        oidToParams.put(sphincsPlus_sha256_128f_simple, sha256_128f_simple);
        oidToParams.put(sphincsPlus_sha256_128s_simple, sha256_128s_simple);
        oidToParams.put(sphincsPlus_sha256_192f_simple, sha256_192f_simple);
        oidToParams.put(sphincsPlus_sha256_192s_simple, sha256_192s_simple);
        oidToParams.put(sphincsPlus_sha256_256f_simple, sha256_256f_simple);
        oidToParams.put(sphincsPlus_sha256_256s_simple, sha256_256s_simple);
        oidToParams.put(sphincsPlus_shake256_128f_robust, shake256_128f);
        oidToParams.put(sphincsPlus_shake256_128s_robust, shake256_128s);
        oidToParams.put(sphincsPlus_shake256_192f_robust, shake256_192f);
        oidToParams.put(sphincsPlus_shake256_192s_robust, shake256_192s);
        oidToParams.put(sphincsPlus_shake256_256f_robust, shake256_256f);
        oidToParams.put(sphincsPlus_shake256_256s_robust, shake256_256s);
        oidToParams.put(sphincsPlus_shake256_128f_simple, shake256_128f_simple);
        oidToParams.put(sphincsPlus_shake256_128s_simple, shake256_128s_simple);
        oidToParams.put(sphincsPlus_shake256_192f_simple, shake256_192f_simple);
        oidToParams.put(sphincsPlus_shake256_192s_simple, shake256_192s_simple);
        oidToParams.put(sphincsPlus_shake256_256f_simple, shake256_256f_simple);
        oidToParams.put(sphincsPlus_shake256_256s_simple, shake256_256s_simple);
        paramsToOid.put(sha256_128f, sphincsPlus_sha256_128f_robust);
        paramsToOid.put(sha256_128s, sphincsPlus_sha256_128s_robust);
        paramsToOid.put(sha256_192f, sphincsPlus_sha256_192f_robust);
        paramsToOid.put(sha256_192s, sphincsPlus_sha256_192s_robust);
        paramsToOid.put(sha256_256f, sphincsPlus_sha256_256f_robust);
        paramsToOid.put(sha256_256s, sphincsPlus_sha256_256s_robust);
        paramsToOid.put(sha256_128f_simple, sphincsPlus_sha256_128f_simple);
        paramsToOid.put(sha256_128s_simple, sphincsPlus_sha256_128s_simple);
        paramsToOid.put(sha256_192f_simple, sphincsPlus_sha256_192f_simple);
        paramsToOid.put(sha256_192s_simple, sphincsPlus_sha256_192s_simple);
        paramsToOid.put(sha256_256f_simple, sphincsPlus_sha256_256f_simple);
        paramsToOid.put(sha256_256s_simple, sphincsPlus_sha256_256s_simple);
        paramsToOid.put(shake256_128f, sphincsPlus_shake256_128f_robust);
        paramsToOid.put(shake256_128s, sphincsPlus_shake256_128s_robust);
        paramsToOid.put(shake256_192f, sphincsPlus_shake256_192f_robust);
        paramsToOid.put(shake256_192s, sphincsPlus_shake256_192s_robust);
        paramsToOid.put(shake256_256f, sphincsPlus_shake256_256f_robust);
        paramsToOid.put(shake256_256s, sphincsPlus_shake256_256s_robust);
        paramsToOid.put(shake256_128f_simple, sphincsPlus_shake256_128f_simple);
        paramsToOid.put(shake256_128s_simple, sphincsPlus_shake256_128s_simple);
        paramsToOid.put(shake256_192f_simple, sphincsPlus_shake256_192f_simple);
        paramsToOid.put(shake256_192s_simple, sphincsPlus_shake256_192s_simple);
        paramsToOid.put(shake256_256f_simple, sphincsPlus_shake256_256f_simple);
        paramsToOid.put(shake256_256s_simple, sphincsPlus_shake256_256s_simple);
    }

    private SPHINCSPlusParameters(String name2, SPHINCSPlusEngine engine2) {
        this.name = name2;
        this.engine = engine2;
    }

    public String getName() {
        return this.name;
    }

    /* access modifiers changed from: package-private */
    public SPHINCSPlusEngine getEngine() {
        return this.engine;
    }

    public static SPHINCSPlusParameters getParams(Integer id) {
        return (SPHINCSPlusParameters) oidToParams.get(id);
    }

    public static Integer getID(SPHINCSPlusParameters params) {
        return (Integer) paramsToOid.get(params);
    }

    public byte[] getEncoded() {
        return Pack.intToBigEndian(getID(this).intValue());
    }
}
