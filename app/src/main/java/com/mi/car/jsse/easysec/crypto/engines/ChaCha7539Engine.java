package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.util.Pack;

public class ChaCha7539Engine extends Salsa20Engine {
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine, com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return "ChaCha7539";
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public int getNonceSize() {
        return 12;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void advanceCounter(long diff) {
        int lo = (int) diff;
        if (((int) (diff >>> 32)) > 0) {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }
        int oldState = this.engineState[12];
        int[] iArr = this.engineState;
        iArr[12] = iArr[12] + lo;
        if (oldState != 0 && this.engineState[12] < oldState) {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void advanceCounter() {
        int[] iArr = this.engineState;
        int i = iArr[12] + 1;
        iArr[12] = i;
        if (i == 0) {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void retreatCounter(long diff) {
        int lo = (int) diff;
        if (((int) (diff >>> 32)) != 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        } else if ((((long) this.engineState[12]) & 4294967295L) >= (((long) lo) & 4294967295L)) {
            int[] iArr = this.engineState;
            iArr[12] = iArr[12] - lo;
        } else {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void retreatCounter() {
        if (this.engineState[12] == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
        int[] iArr = this.engineState;
        iArr[12] = iArr[12] - 1;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public long getCounter() {
        return ((long) this.engineState[12]) & 4294967295L;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void resetCounter() {
        this.engineState[12] = 0;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void setKey(byte[] keyBytes, byte[] ivBytes) {
        if (keyBytes != null) {
            if (keyBytes.length != 32) {
                throw new IllegalArgumentException(getAlgorithmName() + " requires 256 bit key");
            }
            packTauOrSigma(keyBytes.length, this.engineState, 0);
            Pack.littleEndianToInt(keyBytes, 0, this.engineState, 4, 8);
        }
        Pack.littleEndianToInt(ivBytes, 0, this.engineState, 13, 3);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void generateKeyStream(byte[] output) {
        ChaChaEngine.chachaCore(this.rounds, this.engineState, this.x);
        Pack.intToLittleEndian(this.x, output, 0);
    }
}
