package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Memoable;
import com.mi.car.jsse.easysec.util.Pack;

public class DSTU7564Digest implements ExtendedDigest, Memoable {
    private static final int NB_1024 = 16;
    private static final int NB_512 = 8;
    private static final int NR_1024 = 14;
    private static final int NR_512 = 10;
    private static final byte[] S0 = {-88, 67, 95, 6, 107, 117, 108, 89, 113, -33, -121, -107, 23, -16, -40, 9, 109, -13, 29, -53, -55, 77, 44, -81, 121, -32, -105, -3, 111, 75, 69, 57, 62, -35, -93, 79, -76, -74, -102, 14, 31, -65, 21, -31, 73, -46, -109, -58, -110, 114, -98, 97, -47, 99, -6, -18, -12, 25, -43, -83, 88, -92, -69, -95, -36, -14, -125, 55, 66, -28, 122, 50, -100, -52, -85, 74, -113, 110, 4, 39, 46, -25, -30, 90, -106, 22, 35, 43, -62, 101, 102, 15, PSSSigner.TRAILER_IMPLICIT, -87, 71, 65, 52, 72, -4, -73, 106, -120, -91, 83, -122, -7, 91, -37, 56, 123, -61, 30, 34, 51, 36, 40, 54, -57, -78, 59, -114, 119, -70, -11, 20, -97, 8, 85, -101, 76, -2, 96, 92, -38, 24, 70, -51, 125, 33, -80, 63, 27, -119, -1, -21, -124, 105, 58, -99, -41, -45, 112, 103, 64, -75, -34, 93, 48, -111, -79, 120, 17, 1, -27, 0, 104, -104, -96, -59, 2, -90, 116, 45, 11, -94, 118, -77, -66, -50, -67, -82, -23, -118, 49, 28, -20, -15, -103, -108, -86, -10, 38, 47, -17, -24, -116, 53, 3, -44, Byte.MAX_VALUE, -5, 5, -63, 94, -112, 32, 61, -126, -9, -22, 10, 13, 126, -8, 80, 26, -60, 7, 87, -72, 60, 98, -29, -56, -84, 82, 100, Tnaf.POW_2_WIDTH, -48, -39, 19, 12, 18, 41, 81, -71, -49, -42, 115, -115, -127, 84, -64, -19, 78, 68, -89, 42, -123, 37, -26, -54, 124, -117, 86, Byte.MIN_VALUE};
    private static final byte[] S1 = {-50, -69, -21, -110, -22, -53, 19, -63, -23, 58, -42, -78, -46, -112, 23, -8, 66, 21, 86, -76, 101, 28, -120, 67, -59, 92, 54, -70, -11, 87, 103, -115, 49, -10, 100, 88, -98, -12, 34, -86, 117, 15, 2, -79, -33, 109, 115, 77, 124, 38, 46, -9, 8, 93, 68, 62, -97, 20, -56, -82, 84, Tnaf.POW_2_WIDTH, -40, PSSSigner.TRAILER_IMPLICIT, 26, 107, 105, -13, -67, 51, -85, -6, -47, -101, 104, 78, 22, -107, -111, -18, 76, 99, -114, 91, -52, 60, 25, -95, -127, 73, 123, -39, 111, 55, 96, -54, -25, 43, 72, -3, -106, 69, -4, 65, 18, 13, 121, -27, -119, -116, -29, 32, 48, -36, -73, 108, 74, -75, 63, -105, -44, 98, 45, 6, -92, -91, -125, 95, 42, -38, -55, 0, 126, -94, 85, -65, 17, -43, -100, -49, 14, 10, 61, 81, 125, -109, 27, -2, -60, 71, 9, -122, 11, -113, -99, 106, 7, -71, -80, -104, 24, 50, 113, 75, -17, 59, 112, -96, -28, 64, -1, -61, -87, -26, 120, -7, -117, 70, Byte.MIN_VALUE, 30, 56, -31, -72, -88, -32, 12, 35, 118, 29, 37, 36, 5, -15, 110, -108, 40, -102, -124, -24, -93, 79, 119, -45, -123, -30, 82, -14, -126, 80, 122, 47, 116, 83, -77, 97, -81, 57, 53, -34, -51, 31, -103, -84, -83, 114, 44, -35, -48, -121, -66, 94, -90, -20, 4, -58, 3, 52, -5, -37, 89, -74, -62, 1, -16, 90, -19, -89, 102, 33, Byte.MAX_VALUE, -118, 39, -57, -64, 41, -41};
    private static final byte[] S2 = {-109, -39, -102, -75, -104, 34, 69, -4, -70, 106, -33, 2, -97, -36, 81, 89, 74, 23, 43, -62, -108, -12, -69, -93, 98, -28, 113, -44, -51, 112, 22, -31, 73, 60, -64, -40, 92, -101, -83, -123, 83, -95, 122, -56, 45, -32, -47, 114, -90, 44, -60, -29, 118, 120, -73, -76, 9, 59, 14, 65, 76, -34, -78, -112, 37, -91, -41, 3, 17, 0, -61, 46, -110, -17, 78, 18, -99, 125, -53, 53, Tnaf.POW_2_WIDTH, -43, 79, -98, 77, -87, 85, -58, -48, 123, 24, -105, -45, 54, -26, 72, 86, -127, -113, 119, -52, -100, -71, -30, -84, -72, 47, 21, -92, 124, -38, 56, 30, 11, 5, -42, 20, 110, 108, 126, 102, -3, -79, -27, 96, -81, 94, 51, -121, -55, -16, 93, 109, 63, -120, -115, -57, -9, 29, -23, -20, -19, Byte.MIN_VALUE, 41, 39, -49, -103, -88, 80, 15, 55, 36, 40, 48, -107, -46, 62, 91, 64, -125, -77, 105, 87, 31, 7, 28, -118, PSSSigner.TRAILER_IMPLICIT, 32, -21, -50, -114, -85, -18, 49, -94, 115, -7, -54, 58, 26, -5, 13, -63, -2, -6, -14, 111, -67, -106, -35, 67, 82, -74, 8, -13, -82, -66, 25, -119, 50, 38, -80, -22, 75, 100, -124, -126, 107, -11, 121, -65, 1, 95, 117, 99, 27, 35, 61, 104, 42, 101, -24, -111, -10, -1, 19, 88, -15, 71, 10, Byte.MAX_VALUE, -59, -89, -25, 97, 90, 6, 70, 68, 66, 4, -96, -37, 57, -122, 84, -86, -116, 52, 33, -117, -8, 12, 116, 103};
    private static final byte[] S3 = {104, -115, -54, 77, 115, 75, 78, 42, -44, 82, 38, -77, 84, 30, 25, 31, 34, 3, 70, 61, 45, 74, 83, -125, 19, -118, -73, -43, 37, 121, -11, -67, 88, 47, 13, 2, -19, 81, -98, 17, -14, 62, 85, 94, -47, 22, 60, 102, 112, 93, -13, 69, 64, -52, -24, -108, 86, 8, -50, 26, 58, -46, -31, -33, -75, 56, 110, 14, -27, -12, -7, -122, -23, 79, -42, -123, 35, -49, 50, -103, 49, 20, -82, -18, -56, 72, -45, 48, -95, -110, 65, -79, 24, -60, 44, 113, 114, 68, 21, -3, 55, -66, 95, -86, -101, -120, -40, -85, -119, -100, -6, 96, -22, PSSSigner.TRAILER_IMPLICIT, 98, 12, 36, -90, -88, -20, 103, 32, -37, 124, 40, -35, -84, 91, 52, 126, Tnaf.POW_2_WIDTH, -15, 123, -113, 99, -96, 5, -102, 67, 119, 33, -65, 39, 9, -61, -97, -74, -41, 41, -62, -21, -64, -92, -117, -116, 29, -5, -1, -63, -78, -105, 46, -8, 101, -10, 117, 7, 4, 73, 51, -28, -39, -71, -48, 66, -57, 108, -112, 0, -114, 111, 80, 1, -59, -38, 71, 63, -51, 105, -94, -30, 122, -89, -58, -109, 15, 10, 6, -26, 43, -106, -93, 28, -81, 106, 18, -124, 57, -25, -80, -126, -9, -2, -99, -121, 92, -127, 53, -34, -76, -91, -4, Byte.MIN_VALUE, -17, -53, -69, 107, 118, -70, 90, 125, 120, 11, -107, -29, -83, 116, -104, 59, 54, 100, 109, -36, -16, 89, -87, 76, 23, Byte.MAX_VALUE, -111, -72, -55, 87, 27, -32, 97};
    private int blockSize;
    private byte[] buf;
    private int bufOff;
    private int columns;
    private int hashSize;
    private long inputBlocks;
    private int rounds;
    private long[] state;
    private long[] tempState1;
    private long[] tempState2;

    public DSTU7564Digest(DSTU7564Digest digest) {
        copyIn(digest);
    }

    private void copyIn(DSTU7564Digest digest) {
        this.hashSize = digest.hashSize;
        this.blockSize = digest.blockSize;
        this.rounds = digest.rounds;
        if (this.columns <= 0 || this.columns != digest.columns) {
            this.columns = digest.columns;
            this.state = Arrays.clone(digest.state);
            this.tempState1 = new long[this.columns];
            this.tempState2 = new long[this.columns];
            this.buf = Arrays.clone(digest.buf);
        } else {
            System.arraycopy(digest.state, 0, this.state, 0, this.columns);
            System.arraycopy(digest.buf, 0, this.buf, 0, this.blockSize);
        }
        this.inputBlocks = digest.inputBlocks;
        this.bufOff = digest.bufOff;
    }

    public DSTU7564Digest(int hashSizeBits) {
        if (hashSizeBits == 256 || hashSizeBits == 384 || hashSizeBits == 512) {
            this.hashSize = hashSizeBits >>> 3;
            if (hashSizeBits > 256) {
                this.columns = 16;
                this.rounds = 14;
            } else {
                this.columns = 8;
                this.rounds = 10;
            }
            this.blockSize = this.columns << 3;
            this.state = new long[this.columns];
            this.state[0] = (long) this.blockSize;
            this.tempState1 = new long[this.columns];
            this.tempState2 = new long[this.columns];
            this.buf = new byte[this.blockSize];
            return;
        }
        throw new IllegalArgumentException("Hash size is not recommended. Use 256/384/512 instead");
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "DSTU7564";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.hashSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return this.blockSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = in;
        if (this.bufOff == this.blockSize) {
            processBlock(this.buf, 0);
            this.bufOff = 0;
            this.inputBlocks++;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        while (this.bufOff != 0 && len > 0) {
            update(in[inOff]);
            len--;
            inOff++;
        }
        if (len > 0) {
            while (len >= this.blockSize) {
                processBlock(in, inOff);
                inOff += this.blockSize;
                len -= this.blockSize;
                this.inputBlocks++;
            }
            int inOff2 = inOff;
            while (len > 0) {
                update(in[inOff2]);
                len--;
                inOff2++;
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        int inputBytes = this.bufOff;
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = Byte.MIN_VALUE;
        int lenPos = this.blockSize - 12;
        if (this.bufOff > lenPos) {
            while (this.bufOff < this.blockSize) {
                byte[] bArr2 = this.buf;
                int i2 = this.bufOff;
                this.bufOff = i2 + 1;
                bArr2[i2] = 0;
            }
            this.bufOff = 0;
            processBlock(this.buf, 0);
        }
        while (this.bufOff < lenPos) {
            byte[] bArr3 = this.buf;
            int i3 = this.bufOff;
            this.bufOff = i3 + 1;
            bArr3[i3] = 0;
        }
        long c = (((this.inputBlocks & 4294967295L) * ((long) this.blockSize)) + ((long) inputBytes)) << 3;
        Pack.intToLittleEndian((int) c, this.buf, this.bufOff);
        this.bufOff += 4;
        Pack.longToLittleEndian((c >>> 32) + (((this.inputBlocks >>> 32) * ((long) this.blockSize)) << 3), this.buf, this.bufOff);
        processBlock(this.buf, 0);
        System.arraycopy(this.state, 0, this.tempState1, 0, this.columns);
        P(this.tempState1);
        for (int col = 0; col < this.columns; col++) {
            long[] jArr = this.state;
            jArr[col] = jArr[col] ^ this.tempState1[col];
        }
        for (int col2 = this.columns - (this.hashSize >>> 3); col2 < this.columns; col2++) {
            Pack.longToLittleEndian(this.state[col2], out, outOff);
            outOff += 8;
        }
        reset();
        return this.hashSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        Arrays.fill(this.state, 0);
        this.state[0] = (long) this.blockSize;
        this.inputBlocks = 0;
        this.bufOff = 0;
    }

    private void processBlock(byte[] input, int inOff) {
        int pos = inOff;
        for (int col = 0; col < this.columns; col++) {
            long word = Pack.littleEndianToLong(input, pos);
            pos += 8;
            this.tempState1[col] = this.state[col] ^ word;
            this.tempState2[col] = word;
        }
        P(this.tempState1);
        Q(this.tempState2);
        for (int col2 = 0; col2 < this.columns; col2++) {
            long[] jArr = this.state;
            jArr[col2] = jArr[col2] ^ (this.tempState1[col2] ^ this.tempState2[col2]);
        }
    }

    private void P(long[] s) {
        for (int round = 0; round < this.rounds; round++) {
            long rc = (long) round;
            for (int col = 0; col < this.columns; col++) {
                s[col] = s[col] ^ rc;
                rc += 16;
            }
            shiftRows(s);
            subBytes(s);
            mixColumns(s);
        }
    }

    private void Q(long[] s) {
        for (int round = 0; round < this.rounds; round++) {
            long rc = (((long) (((this.columns - 1) << 4) ^ round)) << 56) | 67818912035696883L;
            for (int col = 0; col < this.columns; col++) {
                s[col] = s[col] + rc;
                rc -= 1152921504606846976L;
            }
            shiftRows(s);
            subBytes(s);
            mixColumns(s);
        }
    }

    private static long mixColumn(long c) {
        long x1 = ((9187201950435737471L & c) << 1) ^ (((-9187201950435737472L & c) >>> 7) * 29);
        long u = rotate(8, c) ^ c;
        long u2 = (u ^ rotate(16, u)) ^ rotate(48, c);
        long v = (u2 ^ c) ^ x1;
        return ((rotate(32, (((4557430888798830399L & v) << 2) ^ (((-9187201950435737472L & v) >>> 6) * 29)) ^ (((4629771061636907072L & v) >>> 6) * 29)) ^ u2) ^ rotate(40, x1)) ^ rotate(48, x1);
    }

    private void mixColumns(long[] s) {
        for (int col = 0; col < this.columns; col++) {
            s[col] = mixColumn(s[col]);
        }
    }

    private static long rotate(int n, long x) {
        return (x >>> n) | (x << (-n));
    }

    private void shiftRows(long[] s) {
        switch (this.columns) {
            case 8:
                long c0 = s[0];
                long c1 = s[1];
                long c2 = s[2];
                long c3 = s[3];
                long c4 = s[4];
                long c5 = s[5];
                long c6 = s[6];
                long c7 = s[7];
                long d = (c0 ^ c4) & -4294967296L;
                long c02 = c0 ^ d;
                long c42 = c4 ^ d;
                long d2 = (c1 ^ c5) & 72057594021150720L;
                long c12 = c1 ^ d2;
                long c52 = c5 ^ d2;
                long d3 = (c2 ^ c6) & 281474976645120L;
                long c22 = c2 ^ d3;
                long c62 = c6 ^ d3;
                long d4 = (c3 ^ c7) & 1099511627520L;
                long c32 = c3 ^ d4;
                long c72 = c7 ^ d4;
                long d5 = (c02 ^ c22) & -281470681808896L;
                long c03 = c02 ^ d5;
                long c23 = c22 ^ d5;
                long d6 = (c12 ^ c32) & 72056494543077120L;
                long c13 = c12 ^ d6;
                long c33 = c32 ^ d6;
                long d7 = (c42 ^ c62) & -281470681808896L;
                long c43 = c42 ^ d7;
                long c63 = c62 ^ d7;
                long d8 = (c52 ^ c72) & 72056494543077120L;
                long c53 = c52 ^ d8;
                long c73 = c72 ^ d8;
                long d9 = (c03 ^ c13) & -71777214294589696L;
                long c04 = c03 ^ d9;
                long c14 = c13 ^ d9;
                long d10 = (c23 ^ c33) & -71777214294589696L;
                long c24 = c23 ^ d10;
                long c34 = c33 ^ d10;
                long d11 = (c43 ^ c53) & -71777214294589696L;
                long c44 = c43 ^ d11;
                long c54 = c53 ^ d11;
                long d12 = (c63 ^ c73) & -71777214294589696L;
                s[0] = c04;
                s[1] = c14;
                s[2] = c24;
                s[3] = c34;
                s[4] = c44;
                s[5] = c54;
                s[6] = c63 ^ d12;
                s[7] = c73 ^ d12;
                return;
            case 16:
                long c00 = s[0];
                long c01 = s[1];
                long c022 = s[2];
                long c032 = s[3];
                long c042 = s[4];
                long c05 = s[5];
                long c06 = s[6];
                long c07 = s[7];
                long c08 = s[8];
                long c09 = s[9];
                long c10 = s[10];
                long c11 = s[11];
                long c122 = s[12];
                long c132 = s[13];
                long c142 = s[14];
                long c15 = s[15];
                long d13 = (c00 ^ c08) & -72057594037927936L;
                long c002 = c00 ^ d13;
                long c082 = c08 ^ d13;
                long d14 = (c01 ^ c09) & -72057594037927936L;
                long c012 = c01 ^ d14;
                long c092 = c09 ^ d14;
                long d15 = (c022 ^ c10) & -281474976710656L;
                long c023 = c022 ^ d15;
                long c102 = c10 ^ d15;
                long d16 = (c032 ^ c11) & -1099511627776L;
                long c033 = c032 ^ d16;
                long c112 = c11 ^ d16;
                long d17 = (c042 ^ c122) & -4294967296L;
                long c043 = c042 ^ d17;
                long c123 = c122 ^ d17;
                long d18 = (c05 ^ c132) & 72057594021150720L;
                long c052 = c05 ^ d18;
                long c133 = c132 ^ d18;
                long d19 = (c06 ^ c142) & 72057594037862400L;
                long c062 = c06 ^ d19;
                long c143 = c142 ^ d19;
                long d20 = (c07 ^ c15) & 72057594037927680L;
                long c072 = c07 ^ d20;
                long c152 = c15 ^ d20;
                long d21 = (c002 ^ c043) & 72057589742960640L;
                long c003 = c002 ^ d21;
                long c044 = c043 ^ d21;
                long d22 = (c012 ^ c052) & -16777216;
                long c013 = c012 ^ d22;
                long c053 = c052 ^ d22;
                long d23 = (c023 ^ c062) & -71776119061282816L;
                long c024 = c023 ^ d23;
                long c063 = c062 ^ d23;
                long d24 = (c033 ^ c072) & -72056494526300416L;
                long c034 = c033 ^ d24;
                long c073 = c072 ^ d24;
                long d25 = (c082 ^ c123) & 72057589742960640L;
                long c083 = c082 ^ d25;
                long c124 = c123 ^ d25;
                long d26 = (c092 ^ c133) & -16777216;
                long c093 = c092 ^ d26;
                long c134 = c133 ^ d26;
                long d27 = (c102 ^ c143) & -71776119061282816L;
                long c103 = c102 ^ d27;
                long c144 = c143 ^ d27;
                long d28 = (c112 ^ c152) & -72056494526300416L;
                long c113 = c112 ^ d28;
                long c153 = c152 ^ d28;
                long d29 = (c003 ^ c024) & -281470681808896L;
                long c004 = c003 ^ d29;
                long c025 = c024 ^ d29;
                long d30 = (c013 ^ c034) & 72056494543077120L;
                long c014 = c013 ^ d30;
                long c035 = c034 ^ d30;
                long d31 = (c044 ^ c063) & -281470681808896L;
                long c045 = c044 ^ d31;
                long c064 = c063 ^ d31;
                long d32 = (c053 ^ c073) & 72056494543077120L;
                long c054 = c053 ^ d32;
                long c074 = c073 ^ d32;
                long d33 = (c083 ^ c103) & -281470681808896L;
                long c084 = c083 ^ d33;
                long c104 = c103 ^ d33;
                long d34 = (c093 ^ c113) & 72056494543077120L;
                long c094 = c093 ^ d34;
                long c114 = c113 ^ d34;
                long d35 = (c124 ^ c144) & -281470681808896L;
                long c125 = c124 ^ d35;
                long c145 = c144 ^ d35;
                long d36 = (c134 ^ c153) & 72056494543077120L;
                long c135 = c134 ^ d36;
                long c154 = c153 ^ d36;
                long d37 = (c004 ^ c014) & -71777214294589696L;
                long c005 = c004 ^ d37;
                long c015 = c014 ^ d37;
                long d38 = (c025 ^ c035) & -71777214294589696L;
                long c026 = c025 ^ d38;
                long c036 = c035 ^ d38;
                long d39 = (c045 ^ c054) & -71777214294589696L;
                long c046 = c045 ^ d39;
                long c055 = c054 ^ d39;
                long d40 = (c064 ^ c074) & -71777214294589696L;
                long c065 = c064 ^ d40;
                long c075 = c074 ^ d40;
                long d41 = (c084 ^ c094) & -71777214294589696L;
                long c085 = c084 ^ d41;
                long c095 = c094 ^ d41;
                long d42 = (c104 ^ c114) & -71777214294589696L;
                long c105 = c104 ^ d42;
                long c115 = c114 ^ d42;
                long d43 = (c125 ^ c135) & -71777214294589696L;
                long c126 = c125 ^ d43;
                long c136 = c135 ^ d43;
                long d44 = (c145 ^ c154) & -71777214294589696L;
                s[0] = c005;
                s[1] = c015;
                s[2] = c026;
                s[3] = c036;
                s[4] = c046;
                s[5] = c055;
                s[6] = c065;
                s[7] = c075;
                s[8] = c085;
                s[9] = c095;
                s[10] = c105;
                s[11] = c115;
                s[12] = c126;
                s[13] = c136;
                s[14] = c145 ^ d44;
                s[15] = c154 ^ d44;
                return;
            default:
                throw new IllegalStateException("unsupported state size: only 512/1024 are allowed");
        }
    }

    private void subBytes(long[] s) {
        for (int i = 0; i < this.columns; i++) {
            long u = s[i];
            int lo = (int) u;
            int hi = (int) (u >>> 32);
            s[i] = (((long) ((S0[lo & GF2Field.MASK] & 255) | ((S1[(lo >>> 8) & GF2Field.MASK] & 255) << 8) | ((S2[(lo >>> 16) & GF2Field.MASK] & 255) << 16) | (S3[lo >>> 24] << 24))) & 4294967295L) | (((long) ((((S0[hi & GF2Field.MASK] & 255) | ((S1[(hi >>> 8) & GF2Field.MASK] & 255) << 8)) | ((S2[(hi >>> 16) & GF2Field.MASK] & 255) << 16)) | (S3[hi >>> 24] << 24))) << 32);
        }
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public Memoable copy() {
        return new DSTU7564Digest(this);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public void reset(Memoable other) {
        copyIn((DSTU7564Digest) other);
    }
}
