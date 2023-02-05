package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.util.Memoable;

public class Zuc256CoreEngine extends Zuc128CoreEngine {
    private static final byte[] EK_d = {34, 47, 36, 42, 109, 64, 64, 64, 64, 64, 64, 64, 64, 82, Tnaf.POW_2_WIDTH, 48};
    private static final byte[] EK_d128 = {35, 47, 37, 42, 109, 64, 64, 64, 64, 64, 64, 64, 64, 82, Tnaf.POW_2_WIDTH, 48};
    private static final byte[] EK_d32 = {34, 47, 37, 42, 109, 64, 64, 64, 64, 64, 64, 64, 64, 82, Tnaf.POW_2_WIDTH, 48};
    private static final byte[] EK_d64 = {35, 47, 36, 42, 109, 64, 64, 64, 64, 64, 64, 64, 64, 82, Tnaf.POW_2_WIDTH, 48};
    private byte[] theD;

    protected Zuc256CoreEngine() {
        this.theD = EK_d;
    }

    protected Zuc256CoreEngine(int pLength) {
        switch (pLength) {
            case 32:
                this.theD = EK_d32;
                return;
            case 64:
                this.theD = EK_d64;
                return;
            case 128:
                this.theD = EK_d128;
                return;
            default:
                throw new IllegalArgumentException("Unsupported length: " + pLength);
        }
    }

    protected Zuc256CoreEngine(Zuc256CoreEngine pSource) {
        super(pSource);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Zuc128CoreEngine
    public int getMaxIterations() {
        return 625;
    }

    @Override // com.mi.car.jsse.easysec.crypto.engines.Zuc128CoreEngine, com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return "Zuc-256";
    }

    private static int MAKEU31(byte a, byte b, byte c, byte d) {
        return ((a & 255) << 23) | ((b & 255) << 16) | ((c & 255) << 8) | (d & 255);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Zuc128CoreEngine
    public void setKeyAndIV(int[] pLFSR, byte[] k, byte[] iv) {
        if (k == null || k.length != 32) {
            throw new IllegalArgumentException("A key of 32 bytes is needed");
        } else if (iv == null || iv.length != 25) {
            throw new IllegalArgumentException("An IV of 25 bytes is needed");
        } else {
            pLFSR[0] = MAKEU31(k[0], this.theD[0], k[21], k[16]);
            pLFSR[1] = MAKEU31(k[1], this.theD[1], k[22], k[17]);
            pLFSR[2] = MAKEU31(k[2], this.theD[2], k[23], k[18]);
            pLFSR[3] = MAKEU31(k[3], this.theD[3], k[24], k[19]);
            pLFSR[4] = MAKEU31(k[4], this.theD[4], k[25], k[20]);
            pLFSR[5] = MAKEU31(iv[0], (byte) (this.theD[5] | (iv[17] & 63)), k[5], k[26]);
            pLFSR[6] = MAKEU31(iv[1], (byte) (this.theD[6] | (iv[18] & 63)), k[6], k[27]);
            pLFSR[7] = MAKEU31(iv[10], (byte) (this.theD[7] | (iv[19] & 63)), k[7], iv[2]);
            pLFSR[8] = MAKEU31(k[8], (byte) (this.theD[8] | (iv[20] & 63)), iv[3], iv[11]);
            pLFSR[9] = MAKEU31(k[9], (byte) (this.theD[9] | (iv[21] & 63)), iv[12], iv[4]);
            pLFSR[10] = MAKEU31(iv[5], (byte) (this.theD[10] | (iv[22] & 63)), k[10], k[28]);
            pLFSR[11] = MAKEU31(k[11], (byte) (this.theD[11] | (iv[23] & 63)), iv[6], iv[13]);
            pLFSR[12] = MAKEU31(k[12], (byte) (this.theD[12] | (iv[24] & 63)), iv[7], iv[14]);
            pLFSR[13] = MAKEU31(k[13], this.theD[13], iv[15], iv[8]);
            pLFSR[14] = MAKEU31(k[14], (byte) (this.theD[14] | ((k[31] >>> 4) & 15)), iv[16], iv[9]);
            pLFSR[15] = MAKEU31(k[15], (byte) (this.theD[15] | (k[31] & 15)), k[30], k[29]);
        }
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable, com.mi.car.jsse.easysec.crypto.engines.Zuc128CoreEngine
    public Memoable copy() {
        return new Zuc256CoreEngine(this);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable, com.mi.car.jsse.easysec.crypto.engines.Zuc128CoreEngine
    public void reset(Memoable pState) {
        super.reset(pState);
        this.theD = ((Zuc256CoreEngine) pState).theD;
    }
}
