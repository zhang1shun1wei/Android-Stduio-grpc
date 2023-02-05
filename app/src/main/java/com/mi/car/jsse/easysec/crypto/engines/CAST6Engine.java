package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.asn1.BERTags;

public final class CAST6Engine extends CAST5Engine {
    protected static final int BLOCK_SIZE = 16;
    protected static final int ROUNDS = 12;
    protected int[] _Km = new int[48];
    protected int[] _Kr = new int[48];
    protected int[] _Tm = new int[BERTags.PRIVATE];
    protected int[] _Tr = new int[BERTags.PRIVATE];
    private int[] _workingKey = new int[8];

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.engines.CAST5Engine
    public String getAlgorithmName() {
        return "CAST6";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.engines.CAST5Engine
    public void reset() {
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.engines.CAST5Engine
    public int getBlockSize() {
        return 16;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.CAST5Engine
    public void setKey(byte[] key) {
        int Cm = 1518500249;
        int Cr = 19;
        for (int i = 0; i < 24; i++) {
            for (int j = 0; j < 8; j++) {
                this._Tm[(i * 8) + j] = Cm;
                Cm += 1859775393;
                this._Tr[(i * 8) + j] = Cr;
                Cr = (Cr + 17) & 31;
            }
        }
        byte[] tmpKey = new byte[64];
        System.arraycopy(key, 0, tmpKey, 0, key.length);
        for (int i2 = 0; i2 < 8; i2++) {
            this._workingKey[i2] = BytesTo32bits(tmpKey, i2 * 4);
        }
        for (int i3 = 0; i3 < 12; i3++) {
            int i22 = i3 * 2 * 8;
            int[] iArr = this._workingKey;
            iArr[6] = iArr[6] ^ F1(this._workingKey[7], this._Tm[i22], this._Tr[i22]);
            int[] iArr2 = this._workingKey;
            iArr2[5] = iArr2[5] ^ F2(this._workingKey[6], this._Tm[i22 + 1], this._Tr[i22 + 1]);
            int[] iArr3 = this._workingKey;
            iArr3[4] = iArr3[4] ^ F3(this._workingKey[5], this._Tm[i22 + 2], this._Tr[i22 + 2]);
            int[] iArr4 = this._workingKey;
            iArr4[3] = iArr4[3] ^ F1(this._workingKey[4], this._Tm[i22 + 3], this._Tr[i22 + 3]);
            int[] iArr5 = this._workingKey;
            iArr5[2] = iArr5[2] ^ F2(this._workingKey[3], this._Tm[i22 + 4], this._Tr[i22 + 4]);
            int[] iArr6 = this._workingKey;
            iArr6[1] = iArr6[1] ^ F3(this._workingKey[2], this._Tm[i22 + 5], this._Tr[i22 + 5]);
            int[] iArr7 = this._workingKey;
            iArr7[0] = iArr7[0] ^ F1(this._workingKey[1], this._Tm[i22 + 6], this._Tr[i22 + 6]);
            int[] iArr8 = this._workingKey;
            iArr8[7] = iArr8[7] ^ F2(this._workingKey[0], this._Tm[i22 + 7], this._Tr[i22 + 7]);
            int i23 = ((i3 * 2) + 1) * 8;
            int[] iArr9 = this._workingKey;
            iArr9[6] = iArr9[6] ^ F1(this._workingKey[7], this._Tm[i23], this._Tr[i23]);
            int[] iArr10 = this._workingKey;
            iArr10[5] = iArr10[5] ^ F2(this._workingKey[6], this._Tm[i23 + 1], this._Tr[i23 + 1]);
            int[] iArr11 = this._workingKey;
            iArr11[4] = iArr11[4] ^ F3(this._workingKey[5], this._Tm[i23 + 2], this._Tr[i23 + 2]);
            int[] iArr12 = this._workingKey;
            iArr12[3] = iArr12[3] ^ F1(this._workingKey[4], this._Tm[i23 + 3], this._Tr[i23 + 3]);
            int[] iArr13 = this._workingKey;
            iArr13[2] = iArr13[2] ^ F2(this._workingKey[3], this._Tm[i23 + 4], this._Tr[i23 + 4]);
            int[] iArr14 = this._workingKey;
            iArr14[1] = iArr14[1] ^ F3(this._workingKey[2], this._Tm[i23 + 5], this._Tr[i23 + 5]);
            int[] iArr15 = this._workingKey;
            iArr15[0] = iArr15[0] ^ F1(this._workingKey[1], this._Tm[i23 + 6], this._Tr[i23 + 6]);
            int[] iArr16 = this._workingKey;
            iArr16[7] = iArr16[7] ^ F2(this._workingKey[0], this._Tm[i23 + 7], this._Tr[i23 + 7]);
            this._Kr[i3 * 4] = this._workingKey[0] & 31;
            this._Kr[(i3 * 4) + 1] = this._workingKey[2] & 31;
            this._Kr[(i3 * 4) + 2] = this._workingKey[4] & 31;
            this._Kr[(i3 * 4) + 3] = this._workingKey[6] & 31;
            this._Km[i3 * 4] = this._workingKey[7];
            this._Km[(i3 * 4) + 1] = this._workingKey[5];
            this._Km[(i3 * 4) + 2] = this._workingKey[3];
            this._Km[(i3 * 4) + 3] = this._workingKey[1];
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.CAST5Engine
    public int encryptBlock(byte[] src, int srcIndex, byte[] dst, int dstIndex) {
        int[] result = new int[4];
        CAST_Encipher(BytesTo32bits(src, srcIndex), BytesTo32bits(src, srcIndex + 4), BytesTo32bits(src, srcIndex + 8), BytesTo32bits(src, srcIndex + 12), result);
        Bits32ToBytes(result[0], dst, dstIndex);
        Bits32ToBytes(result[1], dst, dstIndex + 4);
        Bits32ToBytes(result[2], dst, dstIndex + 8);
        Bits32ToBytes(result[3], dst, dstIndex + 12);
        return 16;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.CAST5Engine
    public int decryptBlock(byte[] src, int srcIndex, byte[] dst, int dstIndex) {
        int[] result = new int[4];
        CAST_Decipher(BytesTo32bits(src, srcIndex), BytesTo32bits(src, srcIndex + 4), BytesTo32bits(src, srcIndex + 8), BytesTo32bits(src, srcIndex + 12), result);
        Bits32ToBytes(result[0], dst, dstIndex);
        Bits32ToBytes(result[1], dst, dstIndex + 4);
        Bits32ToBytes(result[2], dst, dstIndex + 8);
        Bits32ToBytes(result[3], dst, dstIndex + 12);
        return 16;
    }

    /* access modifiers changed from: protected */
    public final void CAST_Encipher(int A, int B, int C, int D, int[] result) {
        for (int i = 0; i < 6; i++) {
            int x = i * 4;
            C ^= F1(D, this._Km[x], this._Kr[x]);
            B ^= F2(C, this._Km[x + 1], this._Kr[x + 1]);
            A ^= F3(B, this._Km[x + 2], this._Kr[x + 2]);
            D ^= F1(A, this._Km[x + 3], this._Kr[x + 3]);
        }
        for (int i2 = 6; i2 < 12; i2++) {
            int x2 = i2 * 4;
            D ^= F1(A, this._Km[x2 + 3], this._Kr[x2 + 3]);
            A ^= F3(B, this._Km[x2 + 2], this._Kr[x2 + 2]);
            B ^= F2(C, this._Km[x2 + 1], this._Kr[x2 + 1]);
            C ^= F1(D, this._Km[x2], this._Kr[x2]);
        }
        result[0] = A;
        result[1] = B;
        result[2] = C;
        result[3] = D;
    }

    /* access modifiers changed from: protected */
    public final void CAST_Decipher(int A, int B, int C, int D, int[] result) {
        for (int i = 0; i < 6; i++) {
            int x = (11 - i) * 4;
            C ^= F1(D, this._Km[x], this._Kr[x]);
            B ^= F2(C, this._Km[x + 1], this._Kr[x + 1]);
            A ^= F3(B, this._Km[x + 2], this._Kr[x + 2]);
            D ^= F1(A, this._Km[x + 3], this._Kr[x + 3]);
        }
        for (int i2 = 6; i2 < 12; i2++) {
            int x2 = (11 - i2) * 4;
            D ^= F1(A, this._Km[x2 + 3], this._Kr[x2 + 3]);
            A ^= F3(B, this._Km[x2 + 2], this._Kr[x2 + 2]);
            B ^= F2(C, this._Km[x2 + 1], this._Kr[x2 + 1]);
            C ^= F1(D, this._Km[x2], this._Kr[x2]);
        }
        result[0] = A;
        result[1] = B;
        result[2] = C;
        result[3] = D;
    }
}
