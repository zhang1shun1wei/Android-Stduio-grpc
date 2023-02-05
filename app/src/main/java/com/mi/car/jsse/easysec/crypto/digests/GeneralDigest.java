package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.util.Memoable;
import com.mi.car.jsse.easysec.util.Pack;

public abstract class GeneralDigest implements ExtendedDigest, Memoable {
    private static final int BYTE_LENGTH = 64;
    private long byteCount;
    private final byte[] xBuf;
    private int xBufOff;

    /* access modifiers changed from: protected */
    public abstract void processBlock();

    /* access modifiers changed from: protected */
    public abstract void processLength(long j);

    /* access modifiers changed from: protected */
    public abstract void processWord(byte[] bArr, int i);

    protected GeneralDigest() {
        this.xBuf = new byte[4];
        this.xBufOff = 0;
    }

    protected GeneralDigest(GeneralDigest t) {
        this.xBuf = new byte[4];
        copyIn(t);
    }

    protected GeneralDigest(byte[] encodedState) {
        this.xBuf = new byte[4];
        System.arraycopy(encodedState, 0, this.xBuf, 0, this.xBuf.length);
        this.xBufOff = Pack.bigEndianToInt(encodedState, 4);
        this.byteCount = Pack.bigEndianToLong(encodedState, 8);
    }

    /* access modifiers changed from: protected */
    public void copyIn(GeneralDigest t) {
        System.arraycopy(t.xBuf, 0, this.xBuf, 0, t.xBuf.length);
        this.xBufOff = t.xBufOff;
        this.byteCount = t.byteCount;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        byte[] bArr = this.xBuf;
        int i = this.xBufOff;
        this.xBufOff = i + 1;
        bArr[i] = in;
        if (this.xBufOff == this.xBuf.length) {
            processWord(this.xBuf, 0);
            this.xBufOff = 0;
        }
        this.byteCount++;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        int len2 = Math.max(0, len);
        int i = 0;
        if (this.xBufOff != 0) {
            while (true) {
                if (i >= len2) {
                    i = i;
                    break;
                }
                byte[] bArr = this.xBuf;
                int i2 = this.xBufOff;
                this.xBufOff = i2 + 1;
                i++;
                bArr[i2] = in[inOff + i];
                if (this.xBufOff == 4) {
                    processWord(this.xBuf, 0);
                    this.xBufOff = 0;
                    break;
                }
            }
        }
        int limit = ((len2 - i) & -4) + i;
        while (i < limit) {
            processWord(in, inOff + i);
            i += 4;
        }
        for (int i3 = i; i3 < len2; i3++) {
            byte[] bArr2 = this.xBuf;
            int i4 = this.xBufOff;
            this.xBufOff = i4 + 1;
            bArr2[i4] = in[inOff + i3];
        }
        this.byteCount += (long) len2;
    }

    public void finish() {
        long bitLength = this.byteCount << 3;
        update(Byte.MIN_VALUE);
        while (this.xBufOff != 0) {
            update((byte) 0);
        }
        processLength(bitLength);
        processBlock();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.byteCount = 0;
        this.xBufOff = 0;
        for (int i = 0; i < this.xBuf.length; i++) {
            this.xBuf[i] = 0;
        }
    }

    /* access modifiers changed from: protected */
    public void populateState(byte[] state) {
        System.arraycopy(this.xBuf, 0, state, 0, this.xBufOff);
        Pack.intToBigEndian(this.xBufOff, state, 4);
        Pack.longToBigEndian(this.byteCount, state, 8);
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return 64;
    }
}
