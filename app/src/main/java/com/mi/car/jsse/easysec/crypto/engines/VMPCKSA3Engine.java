package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

public class VMPCKSA3Engine extends VMPCEngine {
    @Override // com.mi.car.jsse.easysec.crypto.engines.VMPCEngine, com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return "VMPC-KSA3";
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.VMPCEngine
    public void initKey(byte[] keyBytes, byte[] ivBytes) {
        this.s = 0;
        this.P = new byte[256];
        for (int i = 0; i < 256; i++) {
            this.P[i] = (byte) i;
        }
        for (int m = 0; m < 768; m++) {
            this.s = this.P[(this.s + this.P[m & GF2Field.MASK] + keyBytes[m % keyBytes.length]) & GF2Field.MASK];
            byte temp = this.P[m & GF2Field.MASK];
            this.P[m & GF2Field.MASK] = this.P[this.s & 255];
            this.P[this.s & 255] = temp;
        }
        for (int m2 = 0; m2 < 768; m2++) {
            this.s = this.P[(this.s + this.P[m2 & GF2Field.MASK] + ivBytes[m2 % ivBytes.length]) & GF2Field.MASK];
            byte temp2 = this.P[m2 & GF2Field.MASK];
            this.P[m2 & GF2Field.MASK] = this.P[this.s & 255];
            this.P[this.s & 255] = temp2;
        }
        for (int m3 = 0; m3 < 768; m3++) {
            this.s = this.P[(this.s + this.P[m3 & GF2Field.MASK] + keyBytes[m3 % keyBytes.length]) & GF2Field.MASK];
            byte temp3 = this.P[m3 & GF2Field.MASK];
            this.P[m3 & GF2Field.MASK] = this.P[this.s & 255];
            this.P[this.s & 255] = temp3;
        }
        this.n = 0;
    }
}
