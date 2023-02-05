package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.engines.Zuc128CoreEngine;

public final class Zuc128Mac implements Mac {
    private static final int TOPBIT = 128;
    private int theByteIndex;
    private final InternalZuc128Engine theEngine = new InternalZuc128Engine();
    private final int[] theKeyStream = new int[2];
    private int theMac;
    private Zuc128CoreEngine theState;
    private int theWordIndex;

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public String getAlgorithmName() {
        return "Zuc128Mac";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int getMacSize() {
        return 4;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters pParams) {
        this.theEngine.init(true, pParams);
        this.theState = (Zuc128CoreEngine) this.theEngine.copy();
        initKeyStream();
    }

    private void initKeyStream() {
        this.theMac = 0;
        for (int i = 0; i < this.theKeyStream.length - 1; i++) {
            this.theKeyStream[i] = this.theEngine.createKeyStreamWord();
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

    private void updateMac(int bitNo) {
        this.theMac ^= getKeyStreamWord(bitNo);
    }

    private int getKeyStreamWord(int bitNo) {
        int myFirst = this.theKeyStream[this.theWordIndex];
        if (bitNo == 0) {
            return myFirst;
        }
        return (myFirst << bitNo) | (this.theKeyStream[(this.theWordIndex + 1) % this.theKeyStream.length] >>> (32 - bitNo));
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte[] in, int inOff, int len) {
        for (int byteNo = 0; byteNo < len; byteNo++) {
            update(in[inOff + byteNo]);
        }
    }

    private int getFinalWord() {
        if (this.theByteIndex != 0) {
            return this.theEngine.createKeyStreamWord();
        }
        this.theWordIndex = (this.theWordIndex + 1) % this.theKeyStream.length;
        return this.theKeyStream[this.theWordIndex];
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int doFinal(byte[] out, int outOff) {
        shift4NextByte();
        this.theMac ^= getKeyStreamWord(this.theByteIndex * 8);
        this.theMac ^= getFinalWord();
        Zuc128CoreEngine.encode32be(this.theMac, out, outOff);
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
    public static class InternalZuc128Engine extends Zuc128CoreEngine {
        private InternalZuc128Engine() {
        }

        /* access modifiers changed from: package-private */
        public int createKeyStreamWord() {
            return super.makeKeyStreamWord();
        }
    }
}
