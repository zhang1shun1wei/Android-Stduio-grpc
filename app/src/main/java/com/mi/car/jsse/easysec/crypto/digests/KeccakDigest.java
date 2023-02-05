package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public class KeccakDigest implements ExtendedDigest {
    private static long[] KeccakRoundConstants = {1, 32898, -9223372036854742902L, -9223372034707259392L, 32907, 2147483649L, -9223372034707259263L, -9223372036854743031L, 138, 136, 2147516425L, 2147483658L, 2147516555L, -9223372036854775669L, -9223372036854742903L, -9223372036854743037L, -9223372036854743038L, -9223372036854775680L, 32778, -9223372034707292150L, -9223372034707259263L, -9223372036854742912L, 2147483649L, -9223372034707259384L};
    protected int bitsInQueue;
    protected byte[] dataQueue;
    protected int fixedOutputLength;
    protected int rate;
    protected boolean squeezing;
    protected long[] state;

    public KeccakDigest() {
        this(288);
    }

    public KeccakDigest(int bitLength) {
        this.state = new long[25];
        this.dataQueue = new byte[BERTags.PRIVATE];
        init(bitLength);
    }

    public KeccakDigest(KeccakDigest source) {
        this.state = new long[25];
        this.dataQueue = new byte[BERTags.PRIVATE];
        System.arraycopy(source.state, 0, this.state, 0, source.state.length);
        System.arraycopy(source.dataQueue, 0, this.dataQueue, 0, source.dataQueue.length);
        this.rate = source.rate;
        this.bitsInQueue = source.bitsInQueue;
        this.fixedOutputLength = source.fixedOutputLength;
        this.squeezing = source.squeezing;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "Keccak-" + this.fixedOutputLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.fixedOutputLength / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        absorb(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        absorb(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        squeeze(out, outOff, (long) this.fixedOutputLength);
        reset();
        return getDigestSize();
    }

    /* access modifiers changed from: protected */
    public int doFinal(byte[] out, int outOff, byte partialByte, int partialBits) {
        if (partialBits > 0) {
            absorbBits(partialByte, partialBits);
        }
        squeeze(out, outOff, (long) this.fixedOutputLength);
        reset();
        return getDigestSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        init(this.fixedOutputLength);
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return this.rate / 8;
    }

    private void init(int bitLength) {
        switch (bitLength) {
            case 128:
            case BERTags.FLAGS:
            case 256:
            case 288:
            case 384:
            case 512:
                initSponge(1600 - (bitLength << 1));
                return;
            default:
                throw new IllegalArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.");
        }
    }

    private void initSponge(int rate2) {
        if (rate2 <= 0 || rate2 >= 1600 || rate2 % 64 != 0) {
            throw new IllegalStateException("invalid rate value");
        }
        this.rate = rate2;
        for (int i = 0; i < this.state.length; i++) {
            this.state[i] = 0;
        }
        Arrays.fill(this.dataQueue, (byte) 0);
        this.bitsInQueue = 0;
        this.squeezing = false;
        this.fixedOutputLength = (1600 - rate2) / 2;
    }

    /* access modifiers changed from: protected */
    public void absorb(byte data) {
        if (this.bitsInQueue % 8 != 0) {
            throw new IllegalStateException("attempt to absorb with odd length queue");
        } else if (this.squeezing) {
            throw new IllegalStateException("attempt to absorb while squeezing");
        } else {
            this.dataQueue[this.bitsInQueue >>> 3] = data;
            int i = this.bitsInQueue + 8;
            this.bitsInQueue = i;
            if (i == this.rate) {
                KeccakAbsorb(this.dataQueue, 0);
                this.bitsInQueue = 0;
            }
        }
    }

    /* access modifiers changed from: protected */
    public void absorb(byte[] data, int off, int len) {
        if (this.bitsInQueue % 8 != 0) {
            throw new IllegalStateException("attempt to absorb with odd length queue");
        } else if (this.squeezing) {
            throw new IllegalStateException("attempt to absorb while squeezing");
        } else {
            int bytesInQueue = this.bitsInQueue >>> 3;
            int rateBytes = this.rate >>> 3;
            int available = rateBytes - bytesInQueue;
            if (len < available) {
                System.arraycopy(data, off, this.dataQueue, bytesInQueue, len);
                this.bitsInQueue += len << 3;
                return;
            }
            int count = 0;
            if (bytesInQueue > 0) {
                System.arraycopy(data, off, this.dataQueue, bytesInQueue, available);
                count = 0 + available;
                KeccakAbsorb(this.dataQueue, 0);
            }
            while (true) {
                int remaining = len - count;
                if (remaining >= rateBytes) {
                    KeccakAbsorb(data, off + count);
                    count += rateBytes;
                } else {
                    System.arraycopy(data, off + count, this.dataQueue, 0, remaining);
                    this.bitsInQueue = remaining << 3;
                    return;
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public void absorbBits(int data, int bits) {
        if (bits < 1 || bits > 7) {
            throw new IllegalArgumentException("'bits' must be in the range 1 to 7");
        } else if (this.bitsInQueue % 8 != 0) {
            throw new IllegalStateException("attempt to absorb with odd length queue");
        } else if (this.squeezing) {
            throw new IllegalStateException("attempt to absorb while squeezing");
        } else {
            this.dataQueue[this.bitsInQueue >>> 3] = (byte) (data & ((1 << bits) - 1));
            this.bitsInQueue += bits;
        }
    }

    private void padAndSwitchToSqueezingPhase() {
        byte[] bArr = this.dataQueue;
        int i = this.bitsInQueue >>> 3;
        bArr[i] = (byte) (bArr[i] | ((byte) (1 << (this.bitsInQueue & 7))));
        int i2 = this.bitsInQueue + 1;
        this.bitsInQueue = i2;
        if (i2 == this.rate) {
            KeccakAbsorb(this.dataQueue, 0);
        } else {
            int full = this.bitsInQueue >>> 6;
            int partial = this.bitsInQueue & 63;
            int off = 0;
            for (int i3 = 0; i3 < full; i3++) {
                long[] jArr = this.state;
                jArr[i3] = jArr[i3] ^ Pack.littleEndianToLong(this.dataQueue, off);
                off += 8;
            }
            if (partial > 0) {
                long[] jArr2 = this.state;
                jArr2[full] = jArr2[full] ^ (Pack.littleEndianToLong(this.dataQueue, off) & ((1 << partial) - 1));
            }
        }
        long[] jArr3 = this.state;
        int i4 = (this.rate - 1) >>> 6;
        jArr3[i4] = jArr3[i4] ^ Long.MIN_VALUE;
        this.bitsInQueue = 0;
        this.squeezing = true;
    }

    /* access modifiers changed from: protected */
    public void squeeze(byte[] output, int offset, long outputLength) {
        if (!this.squeezing) {
            padAndSwitchToSqueezingPhase();
        }
        if (outputLength % 8 != 0) {
            throw new IllegalStateException("outputLength not a multiple of 8");
        }
        long i = 0;
        while (i < outputLength) {
            if (this.bitsInQueue == 0) {
                KeccakExtract();
            }
            int partialBlock = (int) Math.min((long) this.bitsInQueue, outputLength - i);
            System.arraycopy(this.dataQueue, (this.rate - this.bitsInQueue) / 8, output, ((int) (i / 8)) + offset, partialBlock / 8);
            this.bitsInQueue -= partialBlock;
            i += (long) partialBlock;
        }
    }

    private void KeccakAbsorb(byte[] data, int off) {
        int count = this.rate >>> 6;
        for (int i = 0; i < count; i++) {
            long[] jArr = this.state;
            jArr[i] = jArr[i] ^ Pack.littleEndianToLong(data, off);
            off += 8;
        }
        KeccakPermutation();
    }

    private void KeccakExtract() {
        KeccakPermutation();
        Pack.longToLittleEndian(this.state, 0, this.rate >>> 6, this.dataQueue, 0);
        this.bitsInQueue = this.rate;
    }

    private void KeccakPermutation() {
        long[] A = this.state;
        long a00 = A[0];
        long a01 = A[1];
        long a02 = A[2];
        long a03 = A[3];
        long a04 = A[4];
        long a05 = A[5];
        long a06 = A[6];
        long a07 = A[7];
        long a08 = A[8];
        long a09 = A[9];
        long a10 = A[10];
        long a11 = A[11];
        long a12 = A[12];
        long a13 = A[13];
        long a14 = A[14];
        long a15 = A[15];
        long a16 = A[16];
        long a17 = A[17];
        long a18 = A[18];
        long a19 = A[19];
        long a20 = A[20];
        long a21 = A[21];
        long a22 = A[22];
        long a23 = A[23];
        long a24 = A[24];
        for (int i = 0; i < 24; i++) {
            long c0 = (((a00 ^ a05) ^ a10) ^ a15) ^ a20;
            long c1 = (((a01 ^ a06) ^ a11) ^ a16) ^ a21;
            long c2 = (((a02 ^ a07) ^ a12) ^ a17) ^ a22;
            long c3 = (((a03 ^ a08) ^ a13) ^ a18) ^ a23;
            long c4 = (((a04 ^ a09) ^ a14) ^ a19) ^ a24;
            long d1 = ((c1 << 1) | (c1 >>> -1)) ^ c4;
            long d2 = ((c2 << 1) | (c2 >>> -1)) ^ c0;
            long d3 = ((c3 << 1) | (c3 >>> -1)) ^ c1;
            long d4 = ((c4 << 1) | (c4 >>> -1)) ^ c2;
            long d0 = ((c0 << 1) | (c0 >>> -1)) ^ c3;
            long a002 = a00 ^ d1;
            long a052 = a05 ^ d1;
            long a102 = a10 ^ d1;
            long a152 = a15 ^ d1;
            long a202 = a20 ^ d1;
            long a012 = a01 ^ d2;
            long a062 = a06 ^ d2;
            long a112 = a11 ^ d2;
            long a162 = a16 ^ d2;
            long a212 = a21 ^ d2;
            long a022 = a02 ^ d3;
            long a072 = a07 ^ d3;
            long a122 = a12 ^ d3;
            long a172 = a17 ^ d3;
            long a222 = a22 ^ d3;
            long a032 = a03 ^ d4;
            long a082 = a08 ^ d4;
            long a132 = a13 ^ d4;
            long a182 = a18 ^ d4;
            long a232 = a23 ^ d4;
            long a042 = a04 ^ d0;
            long a092 = a09 ^ d0;
            long a142 = a14 ^ d0;
            long a192 = a19 ^ d0;
            long a242 = a24 ^ d0;
            long c12 = (a012 << 1) | (a012 >>> 63);
            long a013 = (a062 << 44) | (a062 >>> 20);
            long a063 = (a092 << 20) | (a092 >>> 44);
            long a093 = (a222 << 61) | (a222 >>> 3);
            long a223 = (a142 << 39) | (a142 >>> 25);
            long a143 = (a202 << 18) | (a202 >>> 46);
            long a203 = (a022 << 62) | (a022 >>> 2);
            long a023 = (a122 << 43) | (a122 >>> 21);
            long a123 = (a132 << 25) | (a132 >>> 39);
            long a133 = (a192 << 8) | (a192 >>> 56);
            long a193 = (a232 << 56) | (a232 >>> 8);
            long a233 = (a152 << 41) | (a152 >>> 23);
            long a153 = (a042 << 27) | (a042 >>> 37);
            long a043 = (a242 << 14) | (a242 >>> 50);
            long a243 = (a212 << 2) | (a212 >>> 62);
            long a213 = (a082 << 55) | (a082 >>> 9);
            long a083 = (a162 << 45) | (a162 >>> 19);
            long a163 = (a052 << 36) | (a052 >>> 28);
            long a053 = (a032 << 28) | (a032 >>> 36);
            long a033 = (a182 << 21) | (a182 >>> 43);
            long a183 = (a172 << 15) | (a172 >>> 49);
            long a173 = (a112 << 10) | (a112 >>> 54);
            long a113 = (a072 << 6) | (a072 >>> 58);
            long a073 = (a102 << 3) | (a102 >>> 61);
            long c02 = a002 ^ ((-1 ^ a013) & a023);
            long c13 = a013 ^ ((-1 ^ a023) & a033);
            a02 = a023 ^ ((-1 ^ a033) & a043);
            a03 = a033 ^ ((-1 ^ a043) & a002);
            a04 = a043 ^ ((-1 ^ a002) & a013);
            a01 = c13;
            long c03 = a053 ^ ((-1 ^ a063) & a073);
            long c14 = a063 ^ ((-1 ^ a073) & a083);
            a07 = a073 ^ ((-1 ^ a083) & a093);
            a08 = a083 ^ ((-1 ^ a093) & a053);
            a09 = a093 ^ ((-1 ^ a053) & a063);
            a05 = c03;
            a06 = c14;
            long c04 = c12 ^ ((-1 ^ a113) & a123);
            long c15 = a113 ^ ((-1 ^ a123) & a133);
            a12 = a123 ^ ((-1 ^ a133) & a143);
            a13 = a133 ^ ((-1 ^ a143) & c12);
            a14 = a143 ^ ((-1 ^ c12) & a113);
            a10 = c04;
            a11 = c15;
            long c05 = a153 ^ ((-1 ^ a163) & a173);
            long c16 = a163 ^ ((-1 ^ a173) & a183);
            a17 = a173 ^ ((-1 ^ a183) & a193);
            a18 = a183 ^ ((-1 ^ a193) & a153);
            a19 = a193 ^ ((-1 ^ a153) & a163);
            a15 = c05;
            a16 = c16;
            long c06 = a203 ^ ((-1 ^ a213) & a223);
            long c17 = a213 ^ ((-1 ^ a223) & a233);
            a22 = a223 ^ ((-1 ^ a233) & a243);
            a23 = a233 ^ ((-1 ^ a243) & a203);
            a24 = a243 ^ ((-1 ^ a203) & a213);
            a20 = c06;
            a21 = c17;
            a00 = c02 ^ KeccakRoundConstants[i];
        }
        A[0] = a00;
        A[1] = a01;
        A[2] = a02;
        A[3] = a03;
        A[4] = a04;
        A[5] = a05;
        A[6] = a06;
        A[7] = a07;
        A[8] = a08;
        A[9] = a09;
        A[10] = a10;
        A[11] = a11;
        A[12] = a12;
        A[13] = a13;
        A[14] = a14;
        A[15] = a15;
        A[16] = a16;
        A[17] = a17;
        A[18] = a18;
        A[19] = a19;
        A[20] = a20;
        A[21] = a21;
        A[22] = a22;
        A[23] = a23;
        A[24] = a24;
    }
}
