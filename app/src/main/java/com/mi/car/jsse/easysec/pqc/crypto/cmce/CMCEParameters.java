package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class CMCEParameters implements CipherParameters {
    private static int[] poly3488 = new int[]{3, 1, 0};
    private static int[] poly4608 = new int[]{10, 9, 6, 0};
    private static int[] poly6688 = new int[]{7, 2, 1, 0};
    private static int[] poly6960 = new int[]{8, 0};
    private static int[] poly8192 = new int[]{7, 2, 1, 0};
    public static final CMCEParameters mceliece348864r3;
    public static final CMCEParameters mceliece348864fr3;
    public static final CMCEParameters mceliece460896r3;
    public static final CMCEParameters mceliece460896fr3;
    public static final CMCEParameters mceliece6688128r3;
    public static final CMCEParameters mceliece6688128fr3;
    public static final CMCEParameters mceliece6960119r3;
    public static final CMCEParameters mceliece6960119fr3;
    public static final CMCEParameters mceliece8192128r3;
    public static final CMCEParameters mceliece8192128fr3;
    private final String name;
    private final int m;
    private final int n;
    private final int t;
    private final int[] poly;
    private final boolean usePivots;
    private final int defaultKeySize;
    private final CMCEEngine engine;

    private CMCEParameters(String name, int m, int n, int t, int[] p, boolean usePivots, int defaultKeySize) {
        this.name = name;
        this.m = m;
        this.n = n;
        this.t = t;
        this.poly = p;
        this.usePivots = usePivots;
        this.defaultKeySize = defaultKeySize;
        this.engine = new CMCEEngine(m, n, t, p, usePivots, defaultKeySize);
    }

    public String getName() {
        return this.name;
    }

    public int getM() {
        return this.m;
    }

    public int getN() {
        return this.n;
    }

    public int getT() {
        return this.t;
    }

    public int getMu() {
        return this.usePivots ? 32 : 0;
    }

    public int getNu() {
        return this.usePivots ? 64 : 0;
    }

    public int getDefaultKeySize() {
        return this.defaultKeySize;
    }

    CMCEEngine getEngine() {
        return this.engine;
    }

    static {
        mceliece348864r3 = new CMCEParameters("mceliece348864", 12, 3488, 64, poly3488, false, 128);
        mceliece348864fr3 = new CMCEParameters("mceliece348864f", 12, 3488, 64, poly3488, true, 128);
        mceliece460896r3 = new CMCEParameters("mceliece460896", 13, 4608, 96, poly4608, false, 192);
        mceliece460896fr3 = new CMCEParameters("mceliece460896f", 13, 4608, 96, poly4608, true, 192);
        mceliece6688128r3 = new CMCEParameters("mceliece6688128", 13, 6688, 128, poly6688, false, 256);
        mceliece6688128fr3 = new CMCEParameters("mceliece6688128f", 13, 6688, 128, poly6688, true, 256);
        mceliece6960119r3 = new CMCEParameters("mceliece6960119", 13, 6960, 119, poly6960, false, 256);
        mceliece6960119fr3 = new CMCEParameters("mceliece6960119f", 13, 6960, 119, poly6960, true, 256);
        mceliece8192128r3 = new CMCEParameters("mceliece8192128", 13, 8192, 128, poly8192, false, 256);
        mceliece8192128fr3 = new CMCEParameters("mceliece8192128f", 13, 8192, 128, poly8192, true, 256);
    }
}
