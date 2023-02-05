package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.engines.Zuc256CoreEngine;

public final class Zuc256Mac implements Mac {
    private static final int TOPBIT = 128;
    private int theByteIndex;
    private final InternalZuc256Engine theEngine;
    private final int[] theKeyStream;
    private final int[] theMac;
    private final int theMacLength;
    private Zuc256CoreEngine theState;
    private int theWordIndex;

    public Zuc256Mac(int pLength) {
        this.theEngine = new InternalZuc256Engine(pLength);
        this.theMacLength = pLength;
        int numWords = pLength / 32;
        this.theMac = new int[numWords];
        this.theKeyStream = new int[(numWords + 1)];
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public String getAlgorithmName() {
        return "Zuc256Mac-" + this.theMacLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int getMacSize() {
        return this.theMacLength / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters pParams) {
        this.theEngine.init(true, pParams);
        this.theState = (Zuc256CoreEngine) this.theEngine.copy();
        initKeyStream();
    }

    private void initKeyStream() {
        for (int i = 0; i < this.theMac.length; i++) {
            this.theMac[i] = this.theEngine.createKeyStreamWord();
        }
        for (int i2 = 0; i2 < this.theKeyStream.length - 1; i2++) {
            this.theKeyStream[i2] = this.theEngine.createKeyStreamWord();
        }
        this.theWordIndex = this.theKeyStream.length - 1;
        this.theByteIndex = 3;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte in) {
        shift4NextByte();
        int bitBase = this.theByteIndex * 8;
        int bitMask = 128;
        int bitNo = 0;
        while (bitMask > 0) {
            if ((in & bitMask) != 0) {
                updateMac(bitBase + bitNo);
            }
            bitMask >>= 1;
            bitNo++;
        }
    }

    private void shift4NextByte() {
        this.theByteIndex = (this.theByteIndex + 1) % 4;
        if (this.theByteIndex == 0) {
            this.theKeyStream[this.theWordIndex] = this.theEngine.createKeyStreamWord();
            this.theWordIndex = (this.theWordIndex + 1) % this.theKeyStream.length;
        }
    }

    private void shift4Final() {
        this.theByteIndex = (this.theByteIndex + 1) % 4;
        if (this.theByteIndex == 0) {
            this.theWordIndex = (this.theWordIndex + 1) % this.theKeyStream.length;
        }
    }

    private void updateMac(int bitNo) {
        for (int wordNo = 0; wordNo < this.theMac.length; wordNo++) {
            int[] iArr = this.theMac;
            iArr[wordNo] = iArr[wordNo] ^ getKeyStreamWord(wordNo, bitNo);
        }
    }

    private int getKeyStreamWord(int wordNo, int bitNo) {
        int myFirst = this.theKeyStream[(this.theWordIndex + wordNo) % this.theKeyStream.length];
        if (bitNo == 0) {
            return myFirst;
        }
        return (myFirst << bitNo) | (this.theKeyStream[((this.theWordIndex + wordNo) + 1) % this.theKeyStream.length] >>> (32 - bitNo));
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte[] in, int inOff, int len) {
        for (int byteNo = 0; byteNo < len; byteNo++) {
            update(in[inOff + byteNo]);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int doFinal(byte[] out, int outOff) {
        shift4Final();
        updateMac(this.theByteIndex * 8);
        for (int i = 0; i < this.theMac.length; i++) {
            Zuc256CoreEngine.encode32be(this.theMac[i], out, (i * 4) + outOff);
        }
        reset();
        return getMacSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void reset() {
        if (this.theState != null) {
            this.theEngine.reset(this.theState);
        }
        initKeyStream();
    }

    /* access modifiers changed from: private */
    public static class InternalZuc256Engine extends Zuc256CoreEngine {
        public InternalZuc256Engine(int pLength) {
            super(pLength);
        }

        /* access modifiers changed from: package-private */
        public int createKeyStreamWord() {
            return super.makeKeyStreamWord();
        }
    }
}
