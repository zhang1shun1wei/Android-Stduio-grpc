package com.mi.car.jsse.easysec.pqc.crypto.frodo;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoMatrixGenerator;

public class FrodoParameters implements CipherParameters {
    private static final short[] cdf_table1344 = {9142, 23462, 30338, 32361, 32725, 32765, Short.MAX_VALUE};
    private static final short[] cdf_table640 = {4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, Short.MAX_VALUE};
    private static final short[] cdf_table976 = {5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, Short.MAX_VALUE};
    public static final FrodoParameters frodokem19888r3 = new FrodoParameters("frodokem19888", 640, 15, 2, cdf_table640, new SHAKEDigest(128), new FrodoMatrixGenerator.Aes128MatrixGenerator(640, 32768), 64);
    public static final FrodoParameters frodokem19888shaker3 = new FrodoParameters("frodokem19888shake", 640, 15, 2, cdf_table640, new SHAKEDigest(128), new FrodoMatrixGenerator.Shake128MatrixGenerator(640, 32768), 64);
    public static final FrodoParameters frodokem31296r3 = new FrodoParameters("frodokem31296", 976, 16, 3, cdf_table976, new SHAKEDigest(256), new FrodoMatrixGenerator.Aes128MatrixGenerator(976, 65536), 96);
    public static final FrodoParameters frodokem31296shaker3 = new FrodoParameters("frodokem31296shake", 976, 16, 3, cdf_table976, new SHAKEDigest(256), new FrodoMatrixGenerator.Shake128MatrixGenerator(976, 65536), 96);
    public static final FrodoParameters frodokem43088r3 = new FrodoParameters("frodokem43088", 1344, 16, 4, cdf_table1344, new SHAKEDigest(256), new FrodoMatrixGenerator.Aes128MatrixGenerator(1344, 65536), 128);
    public static final FrodoParameters frodokem43088shaker3 = new FrodoParameters("frodokem43088shake", 1344, 16, 4, cdf_table1344, new SHAKEDigest(256), new FrodoMatrixGenerator.Shake128MatrixGenerator(1344, 65536), 128);
    private final int B;
    private final int D;
    private final short[] cdf_table;
    private final int defaultKeySize;
    private final Xof digest;
    private final FrodoEngine engine;
    private final FrodoMatrixGenerator mGen;
    private final int n;
    private final String name;

    public FrodoParameters(String name2, int n2, int D2, int B2, short[] cdf_table2, Xof digest2, FrodoMatrixGenerator mGen2, int defaultKeySize2) {
        this.name = name2;
        this.n = n2;
        this.D = D2;
        this.B = B2;
        this.cdf_table = cdf_table2;
        this.digest = digest2;
        this.mGen = mGen2;
        this.defaultKeySize = defaultKeySize2;
        this.engine = new FrodoEngine(n2, D2, B2, cdf_table2, digest2, mGen2);
    }

    /* access modifiers changed from: package-private */
    public FrodoEngine getEngine() {
        return this.engine;
    }

    public int getN() {
        return this.n;
    }

    public String getName() {
        return this.name;
    }

    public int getD() {
        return this.D;
    }

    public int getB() {
        return this.B;
    }

    public short[] getCdf_table() {
        return this.cdf_table;
    }

    public Xof getDigest() {
        return this.digest;
    }

    public int getDefaultKeySize() {
        return this.defaultKeySize;
    }

    public FrodoMatrixGenerator getmGen() {
        return this.mGen;
    }
}
