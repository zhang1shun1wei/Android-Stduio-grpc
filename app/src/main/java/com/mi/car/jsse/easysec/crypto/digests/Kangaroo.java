package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public final class Kangaroo {
    private static final int DIGESTLEN = 32;

    public static class KangarooTwelve extends KangarooBase {
        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int doFinal(byte[] bArr, int i) {
            return super.doFinal(bArr, i);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Xof, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int doFinal(byte[] bArr, int i, int i2) {
            return super.doFinal(bArr, i, i2);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Xof, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int doOutput(byte[] bArr, int i, int i2) {
            return super.doOutput(bArr, i, i2);
        }

        @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int getByteLength() {
            return super.getByteLength();
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int getDigestSize() {
            return super.getDigestSize();
        }

        @Override // com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ void init(KangarooParameters kangarooParameters) {
            super.init(kangarooParameters);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ void update(byte b) {
            super.update(b);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ void update(byte[] bArr, int i, int i2) {
            super.update(bArr, i, i2);
        }

        public KangarooTwelve() {
            this(32);
        }

        public KangarooTwelve(int pLength) {
            super(128, 12, pLength);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest
        public String getAlgorithmName() {
            return "KangarooTwelve";
        }
    }

    public static class MarsupilamiFourteen extends KangarooBase {
        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int doFinal(byte[] bArr, int i) {
            return super.doFinal(bArr, i);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Xof, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int doFinal(byte[] bArr, int i, int i2) {
            return super.doFinal(bArr, i, i2);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Xof, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int doOutput(byte[] bArr, int i, int i2) {
            return super.doOutput(bArr, i, i2);
        }

        @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int getByteLength() {
            return super.getByteLength();
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ int getDigestSize() {
            return super.getDigestSize();
        }

        @Override // com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ void init(KangarooParameters kangarooParameters) {
            super.init(kangarooParameters);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ void reset() {
            super.reset();
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ void update(byte b) {
            super.update(b);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.Kangaroo.KangarooBase
        public /* bridge */ /* synthetic */ void update(byte[] bArr, int i, int i2) {
            super.update(bArr, i, i2);
        }

        public MarsupilamiFourteen() {
            this(32);
        }

        public MarsupilamiFourteen(int pLength) {
            super(256, 14, pLength);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest
        public String getAlgorithmName() {
            return "MarsupilamiFourteen";
        }
    }

    public static class KangarooParameters implements CipherParameters {
        private byte[] thePersonal;

        public byte[] getPersonalisation() {
            return Arrays.clone(this.thePersonal);
        }

        public static class Builder {
            private byte[] thePersonal;

            public Builder setPersonalisation(byte[] pPersonal) {
                this.thePersonal = Arrays.clone(pPersonal);
                return this;
            }

            public KangarooParameters build() {
                KangarooParameters myParams = new KangarooParameters();
                if (this.thePersonal != null) {
                    myParams.thePersonal = this.thePersonal;
                }
                return myParams;
            }
        }
    }

    static abstract class KangarooBase implements ExtendedDigest, Xof {
        private static final int BLKSIZE = 8192;
        private static final byte[] FINAL = {-1, -1, 6};
        private static final byte[] FIRST = {3, 0, 0, 0, 0, 0, 0, 0};
        private static final byte[] INTERMEDIATE = {11};
        private static final byte[] SINGLE = {7};
        private final byte[] singleByte = new byte[1];
        private boolean squeezing;
        private final int theChainLen;
        private int theCurrNode;
        private final KangarooSponge theLeaf;
        private byte[] thePersonal;
        private int theProcessed;
        private final KangarooSponge theTree;

        KangarooBase(int pStrength, int pRounds, int pLength) {
            this.theTree = new KangarooSponge(pStrength, pRounds);
            this.theLeaf = new KangarooSponge(pStrength, pRounds);
            this.theChainLen = pStrength >> 2;
            buildPersonal(null);
        }

        private void buildPersonal(byte[] pPersonal) {
            byte[] copyOf;
            int myLen = pPersonal == null ? 0 : pPersonal.length;
            byte[] myEnc = lengthEncode((long) myLen);
            if (pPersonal == null) {
                copyOf = new byte[(myEnc.length + myLen)];
            } else {
                copyOf = Arrays.copyOf(pPersonal, myEnc.length + myLen);
            }
            this.thePersonal = copyOf;
            System.arraycopy(myEnc, 0, this.thePersonal, myLen, myEnc.length);
        }

        @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
        public int getByteLength() {
            return this.theTree.theRateBytes;
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest
        public int getDigestSize() {
            return this.theChainLen >> 1;
        }

        public void init(KangarooParameters pParams) {
            buildPersonal(pParams.getPersonalisation());
            reset();
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest
        public void update(byte pIn) {
            this.singleByte[0] = pIn;
            update(this.singleByte, 0, 1);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest
        public void update(byte[] pIn, int pInOff, int pLen) {
            processData(pIn, pInOff, pLen);
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest
        public int doFinal(byte[] pOut, int pOutOffset) {
            return doFinal(pOut, pOutOffset, getDigestSize());
        }

        @Override // com.mi.car.jsse.easysec.crypto.Xof
        public int doFinal(byte[] pOut, int pOutOffset, int pOutLen) {
            if (this.squeezing) {
                throw new IllegalStateException("Already outputting");
            }
            int length = doOutput(pOut, pOutOffset, pOutLen);
            reset();
            return length;
        }

        @Override // com.mi.car.jsse.easysec.crypto.Xof
        public int doOutput(byte[] pOut, int pOutOffset, int pOutLen) {
            if (!this.squeezing) {
                switchToSqueezing();
            }
            if (pOutLen < 0) {
                throw new IllegalArgumentException("Invalid output length");
            }
            this.theTree.squeeze(pOut, pOutOffset, pOutLen);
            return pOutLen;
        }

        private void processData(byte[] pIn, int pInOffSet, int pLen) {
            if (this.squeezing) {
                throw new IllegalStateException("attempt to absorb while squeezing");
            }
            KangarooSponge mySponge = this.theCurrNode == 0 ? this.theTree : this.theLeaf;
            int mySpace = 8192 - this.theProcessed;
            if (mySpace >= pLen) {
                mySponge.absorb(pIn, pInOffSet, pLen);
                this.theProcessed += pLen;
                return;
            }
            if (mySpace > 0) {
                mySponge.absorb(pIn, pInOffSet, mySpace);
                this.theProcessed += mySpace;
            }
            int myProcessed = mySpace;
            while (myProcessed < pLen) {
                if (this.theProcessed == BLKSIZE) {
                    switchLeaf(true);
                }
                int myDataLen = Math.min(pLen - myProcessed, (int) BLKSIZE);
                this.theLeaf.absorb(pIn, pInOffSet + myProcessed, myDataLen);
                this.theProcessed += myDataLen;
                myProcessed += myDataLen;
            }
        }

        @Override // com.mi.car.jsse.easysec.crypto.Digest
        public void reset() {
            this.theTree.initSponge();
            this.theLeaf.initSponge();
            this.theCurrNode = 0;
            this.theProcessed = 0;
            this.squeezing = false;
        }

        private void switchLeaf(boolean pMoreToCome) {
            if (this.theCurrNode == 0) {
                this.theTree.absorb(FIRST, 0, FIRST.length);
            } else {
                this.theLeaf.absorb(INTERMEDIATE, 0, INTERMEDIATE.length);
                byte[] myHash = new byte[this.theChainLen];
                this.theLeaf.squeeze(myHash, 0, this.theChainLen);
                this.theTree.absorb(myHash, 0, this.theChainLen);
                this.theLeaf.initSponge();
            }
            if (pMoreToCome) {
                this.theCurrNode++;
            }
            this.theProcessed = 0;
        }

        private void switchToSqueezing() {
            processData(this.thePersonal, 0, this.thePersonal.length);
            if (this.theCurrNode == 0) {
                switchSingle();
            } else {
                switchFinal();
            }
        }

        private void switchSingle() {
            this.theTree.absorb(SINGLE, 0, 1);
            this.theTree.padAndSwitchToSqueezingPhase();
        }

        private void switchFinal() {
            switchLeaf(false);
            byte[] myLength = lengthEncode((long) this.theCurrNode);
            this.theTree.absorb(myLength, 0, myLength.length);
            this.theTree.absorb(FINAL, 0, FINAL.length);
            this.theTree.padAndSwitchToSqueezingPhase();
        }

        private static byte[] lengthEncode(long strLen) {
            byte n = 0;
            long v = strLen;
            if (v != 0) {
                n = 1;
                while (true) {
                    v >>= 8;
                    if (v == 0) {
                        break;
                    }
                    n = (byte) (n + 1);
                }
            }
            byte[] b = new byte[(n + 1)];
            b[n] = n;
            for (int i = 0; i < n; i++) {
                b[i] = (byte) ((int) (strLen >> (((n - i) - 1) * 8)));
            }
            return b;
        }
    }

    /* access modifiers changed from: private */
    public static class KangarooSponge {
        private static long[] KeccakRoundConstants = {1, 32898, -9223372036854742902L, -9223372034707259392L, 32907, 2147483649L, -9223372034707259263L, -9223372036854743031L, 138, 136, 2147516425L, 2147483658L, 2147516555L, -9223372036854775669L, -9223372036854742903L, -9223372036854743037L, -9223372036854743038L, -9223372036854775680L, 32778, -9223372034707292150L, -9223372034707259263L, -9223372036854742912L, 2147483649L, -9223372034707259384L};
        private int bytesInQueue;
        private boolean squeezing;
        private final byte[] theQueue;
        private final int theRateBytes;
        private final int theRounds;
        private final long[] theState = new long[25];

        KangarooSponge(int pStrength, int pRounds) {
            this.theRateBytes = (1600 - (pStrength << 1)) >> 3;
            this.theRounds = pRounds;
            this.theQueue = new byte[this.theRateBytes];
            initSponge();
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void initSponge() {
            Arrays.fill(this.theState, 0);
            Arrays.fill(this.theQueue, (byte) 0);
            this.bytesInQueue = 0;
            this.squeezing = false;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void absorb(byte[] data, int off, int len) {
            if (this.squeezing) {
                throw new IllegalStateException("attempt to absorb while squeezing");
            }
            int count = 0;
            while (count < len) {
                if (this.bytesInQueue != 0 || count > len - this.theRateBytes) {
                    int partialBlock = Math.min(this.theRateBytes - this.bytesInQueue, len - count);
                    System.arraycopy(data, off + count, this.theQueue, this.bytesInQueue, partialBlock);
                    this.bytesInQueue += partialBlock;
                    count += partialBlock;
                    if (this.bytesInQueue == this.theRateBytes) {
                        KangarooAbsorb(this.theQueue, 0);
                        this.bytesInQueue = 0;
                    }
                } else {
                    do {
                        KangarooAbsorb(data, off + count);
                        count += this.theRateBytes;
                    } while (count <= len - this.theRateBytes);
                }
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void padAndSwitchToSqueezingPhase() {
            for (int i = this.bytesInQueue; i < this.theRateBytes; i++) {
                this.theQueue[i] = 0;
            }
            byte[] bArr = this.theQueue;
            int i2 = this.theRateBytes - 1;
            bArr[i2] = (byte) (bArr[i2] ^ 128);
            KangarooAbsorb(this.theQueue, 0);
            KangarooExtract();
            this.bytesInQueue = this.theRateBytes;
            this.squeezing = true;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void squeeze(byte[] output, int offset, int outputLength) {
            if (!this.squeezing) {
                padAndSwitchToSqueezingPhase();
            }
            int i = 0;
            while (i < outputLength) {
                if (this.bytesInQueue == 0) {
                    KangarooPermutation();
                    KangarooExtract();
                    this.bytesInQueue = this.theRateBytes;
                }
                int partialBlock = Math.min(this.bytesInQueue, outputLength - i);
                System.arraycopy(this.theQueue, this.theRateBytes - this.bytesInQueue, output, offset + i, partialBlock);
                this.bytesInQueue -= partialBlock;
                i += partialBlock;
            }
        }

        private void KangarooAbsorb(byte[] data, int off) {
            int count = this.theRateBytes >> 3;
            int offSet = off;
            for (int i = 0; i < count; i++) {
                long[] jArr = this.theState;
                jArr[i] = jArr[i] ^ Pack.littleEndianToLong(data, offSet);
                offSet += 8;
            }
            KangarooPermutation();
        }

        private void KangarooExtract() {
            Pack.longToLittleEndian(this.theState, 0, this.theRateBytes >> 3, this.theQueue, 0);
        }

        private void KangarooPermutation() {
            long[] A = this.theState;
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
            int myBase = KeccakRoundConstants.length - this.theRounds;
            for (int i = 0; i < this.theRounds; i++) {
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
                a00 = c02 ^ KeccakRoundConstants[myBase + i];
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
}
