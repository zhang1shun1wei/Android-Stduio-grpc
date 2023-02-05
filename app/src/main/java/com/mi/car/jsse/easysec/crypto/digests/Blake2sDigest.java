package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public class Blake2sDigest implements ExtendedDigest {
    private static final int BLOCK_LENGTH_BYTES = 64;
    private static final int ROUNDS = 10;
    private static final int[] blake2s_IV = {1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372, 528734635, 1541459225};
    private static final byte[][] blake2s_sigma = {new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, new byte[]{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}, new byte[]{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, new byte[]{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}, new byte[]{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, new byte[]{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}, new byte[]{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, new byte[]{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}, new byte[]{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, new byte[]{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};
    private byte[] buffer;
    private int bufferPos;
    private int[] chainValue;
    private int depth;
    private int digestLength;
    private int f0;
    private int fanout;
    private int innerHashLength;
    private int[] internalState;
    private byte[] key;
    private int keyLength;
    private int leafLength;
    private int nodeDepth;
    private long nodeOffset;
    private byte[] personalization;
    private byte[] salt;
    private int t0;
    private int t1;

    public Blake2sDigest() {
        this(256);
    }

    public Blake2sDigest(Blake2sDigest digest) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.t0 = 0;
        this.t1 = 0;
        this.f0 = 0;
        this.bufferPos = digest.bufferPos;
        this.buffer = Arrays.clone(digest.buffer);
        this.keyLength = digest.keyLength;
        this.key = Arrays.clone(digest.key);
        this.digestLength = digest.digestLength;
        this.internalState = Arrays.clone(this.internalState);
        this.chainValue = Arrays.clone(digest.chainValue);
        this.t0 = digest.t0;
        this.t1 = digest.t1;
        this.f0 = digest.f0;
        this.salt = Arrays.clone(digest.salt);
        this.personalization = Arrays.clone(digest.personalization);
        this.fanout = digest.fanout;
        this.depth = digest.depth;
        this.leafLength = digest.leafLength;
        this.nodeOffset = digest.nodeOffset;
        this.nodeDepth = digest.nodeDepth;
        this.innerHashLength = digest.innerHashLength;
    }

    public Blake2sDigest(int digestBits) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.t0 = 0;
        this.t1 = 0;
        this.f0 = 0;
        if (digestBits < 8 || digestBits > 256 || digestBits % 8 != 0) {
            throw new IllegalArgumentException("BLAKE2s digest bit length must be a multiple of 8 and not greater than 256");
        }
        this.digestLength = digestBits / 8;
        init(null, null, null);
    }

    public Blake2sDigest(byte[] key2) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.t0 = 0;
        this.t1 = 0;
        this.f0 = 0;
        init(null, null, key2);
    }

    public Blake2sDigest(byte[] key2, int digestBytes, byte[] salt2, byte[] personalization2) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.t0 = 0;
        this.t1 = 0;
        this.f0 = 0;
        if (digestBytes < 1 || digestBytes > 32) {
            throw new IllegalArgumentException("Invalid digest length (required: 1 - 32)");
        }
        this.digestLength = digestBytes;
        init(salt2, personalization2, key2);
    }

    Blake2sDigest(int digestBytes, byte[] key2, byte[] salt2, byte[] personalization2, long offset) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.t0 = 0;
        this.t1 = 0;
        this.f0 = 0;
        this.digestLength = digestBytes;
        this.nodeOffset = offset;
        init(salt2, personalization2, key2);
    }

    Blake2sDigest(int digestBytes, int hashLength, long offset) {
        this.digestLength = 32;
        this.keyLength = 0;
        this.salt = null;
        this.personalization = null;
        this.key = null;
        this.fanout = 1;
        this.depth = 1;
        this.leafLength = 0;
        this.nodeOffset = 0;
        this.nodeDepth = 0;
        this.innerHashLength = 0;
        this.buffer = null;
        this.bufferPos = 0;
        this.internalState = new int[16];
        this.chainValue = null;
        this.t0 = 0;
        this.t1 = 0;
        this.f0 = 0;
        this.digestLength = digestBytes;
        this.nodeOffset = offset;
        this.fanout = 0;
        this.depth = 0;
        this.leafLength = hashLength;
        this.innerHashLength = hashLength;
        this.nodeDepth = 0;
        init(null, null, null);
    }

    private void init(byte[] salt2, byte[] personalization2, byte[] key2) {
        this.buffer = new byte[64];
        if (key2 != null && key2.length > 0) {
            if (key2.length > 32) {
                throw new IllegalArgumentException("Keys > 32 bytes are not supported");
            }
            this.key = new byte[key2.length];
            System.arraycopy(key2, 0, this.key, 0, key2.length);
            this.keyLength = key2.length;
            System.arraycopy(key2, 0, this.buffer, 0, key2.length);
            this.bufferPos = 64;
        }
        if (this.chainValue == null) {
            this.chainValue = new int[8];
            this.chainValue[0] = blake2s_IV[0] ^ ((this.digestLength | (this.keyLength << 8)) | ((this.fanout << 16) | (this.depth << 24)));
            this.chainValue[1] = blake2s_IV[1] ^ this.leafLength;
            int nofHi = (int) (this.nodeOffset >> 32);
            this.chainValue[2] = blake2s_IV[2] ^ ((int) this.nodeOffset);
            this.chainValue[3] = blake2s_IV[3] ^ (((this.nodeDepth << 16) | nofHi) | (this.innerHashLength << 24));
            this.chainValue[4] = blake2s_IV[4];
            this.chainValue[5] = blake2s_IV[5];
            if (salt2 != null) {
                if (salt2.length != 8) {
                    throw new IllegalArgumentException("Salt length must be exactly 8 bytes");
                }
                this.salt = new byte[8];
                System.arraycopy(salt2, 0, this.salt, 0, salt2.length);
                int[] iArr = this.chainValue;
                iArr[4] = iArr[4] ^ Pack.littleEndianToInt(salt2, 0);
                int[] iArr2 = this.chainValue;
                iArr2[5] = iArr2[5] ^ Pack.littleEndianToInt(salt2, 4);
            }
            this.chainValue[6] = blake2s_IV[6];
            this.chainValue[7] = blake2s_IV[7];
            if (personalization2 == null) {
                return;
            }
            if (personalization2.length != 8) {
                throw new IllegalArgumentException("Personalization length must be exactly 8 bytes");
            }
            this.personalization = new byte[8];
            System.arraycopy(personalization2, 0, this.personalization, 0, personalization2.length);
            int[] iArr3 = this.chainValue;
            iArr3[6] = iArr3[6] ^ Pack.littleEndianToInt(personalization2, 0);
            int[] iArr4 = this.chainValue;
            iArr4[7] = iArr4[7] ^ Pack.littleEndianToInt(personalization2, 4);
        }
    }

    private void initializeInternalState() {
        System.arraycopy(this.chainValue, 0, this.internalState, 0, this.chainValue.length);
        System.arraycopy(blake2s_IV, 0, this.internalState, this.chainValue.length, 4);
        this.internalState[12] = this.t0 ^ blake2s_IV[4];
        this.internalState[13] = this.t1 ^ blake2s_IV[5];
        this.internalState[14] = this.f0 ^ blake2s_IV[6];
        this.internalState[15] = blake2s_IV[7];
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte b) {
        if (64 - this.bufferPos == 0) {
            this.t0 += 64;
            if (this.t0 == 0) {
                this.t1++;
            }
            compress(this.buffer, 0);
            Arrays.fill(this.buffer, (byte) 0);
            this.buffer[0] = b;
            this.bufferPos = 1;
            return;
        }
        this.buffer[this.bufferPos] = b;
        this.bufferPos++;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] message, int offset, int len) {
        if (message != null && len != 0) {
            int remainingLength = 0;
            if (this.bufferPos != 0) {
                remainingLength = 64 - this.bufferPos;
                if (remainingLength < len) {
                    System.arraycopy(message, offset, this.buffer, this.bufferPos, remainingLength);
                    this.t0 += 64;
                    if (this.t0 == 0) {
                        this.t1++;
                    }
                    compress(this.buffer, 0);
                    this.bufferPos = 0;
                    Arrays.fill(this.buffer, (byte) 0);
                } else {
                    System.arraycopy(message, offset, this.buffer, this.bufferPos, len);
                    this.bufferPos += len;
                    return;
                }
            }
            int blockWiseLastPos = (offset + len) - 64;
            int messagePos = offset + remainingLength;
            while (messagePos < blockWiseLastPos) {
                this.t0 += 64;
                if (this.t0 == 0) {
                    this.t1++;
                }
                compress(message, messagePos);
                messagePos += 64;
            }
            System.arraycopy(message, messagePos, this.buffer, 0, (offset + len) - messagePos);
            this.bufferPos += (offset + len) - messagePos;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOffset) {
        this.f0 = -1;
        this.t0 += this.bufferPos;
        if (this.t0 < 0 && this.bufferPos > (-this.t0)) {
            this.t1++;
        }
        compress(this.buffer, 0);
        Arrays.fill(this.buffer, (byte) 0);
        Arrays.fill(this.internalState, 0);
        int i = 0;
        while (i < this.chainValue.length && i * 4 < this.digestLength) {
            byte[] bytes = Pack.intToLittleEndian(this.chainValue[i]);
            if (i * 4 < this.digestLength - 4) {
                System.arraycopy(bytes, 0, out, (i * 4) + outOffset, 4);
            } else {
                System.arraycopy(bytes, 0, out, (i * 4) + outOffset, this.digestLength - (i * 4));
            }
            i++;
        }
        Arrays.fill(this.chainValue, 0);
        reset();
        return this.digestLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.bufferPos = 0;
        this.f0 = 0;
        this.t0 = 0;
        this.t1 = 0;
        this.chainValue = null;
        Arrays.fill(this.buffer, (byte) 0);
        if (this.key != null) {
            System.arraycopy(this.key, 0, this.buffer, 0, this.key.length);
            this.bufferPos = 64;
        }
        init(this.salt, this.personalization, this.key);
    }

    private void compress(byte[] message, int messagePos) {
        initializeInternalState();
        int[] m = new int[16];
        for (int j = 0; j < 16; j++) {
            m[j] = Pack.littleEndianToInt(message, (j * 4) + messagePos);
        }
        for (int round = 0; round < 10; round++) {
            G(m[blake2s_sigma[round][0]], m[blake2s_sigma[round][1]], 0, 4, 8, 12);
            G(m[blake2s_sigma[round][2]], m[blake2s_sigma[round][3]], 1, 5, 9, 13);
            G(m[blake2s_sigma[round][4]], m[blake2s_sigma[round][5]], 2, 6, 10, 14);
            G(m[blake2s_sigma[round][6]], m[blake2s_sigma[round][7]], 3, 7, 11, 15);
            G(m[blake2s_sigma[round][8]], m[blake2s_sigma[round][9]], 0, 5, 10, 15);
            G(m[blake2s_sigma[round][10]], m[blake2s_sigma[round][11]], 1, 6, 11, 12);
            G(m[blake2s_sigma[round][12]], m[blake2s_sigma[round][13]], 2, 7, 8, 13);
            G(m[blake2s_sigma[round][14]], m[blake2s_sigma[round][15]], 3, 4, 9, 14);
        }
        for (int offset = 0; offset < this.chainValue.length; offset++) {
            this.chainValue[offset] = (this.chainValue[offset] ^ this.internalState[offset]) ^ this.internalState[offset + 8];
        }
    }

    private void G(int m1, int m2, int posA, int posB, int posC, int posD) {
        this.internalState[posA] = this.internalState[posA] + this.internalState[posB] + m1;
        this.internalState[posD] = rotr32(this.internalState[posD] ^ this.internalState[posA], 16);
        this.internalState[posC] = this.internalState[posC] + this.internalState[posD];
        this.internalState[posB] = rotr32(this.internalState[posB] ^ this.internalState[posC], 12);
        this.internalState[posA] = this.internalState[posA] + this.internalState[posB] + m2;
        this.internalState[posD] = rotr32(this.internalState[posD] ^ this.internalState[posA], 8);
        this.internalState[posC] = this.internalState[posC] + this.internalState[posD];
        this.internalState[posB] = rotr32(this.internalState[posB] ^ this.internalState[posC], 7);
    }

    private int rotr32(int x, int rot) {
        return (x >>> rot) | (x << (32 - rot));
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "BLAKE2s";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.digestLength;
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return 64;
    }

    public void clearKey() {
        if (this.key != null) {
            Arrays.fill(this.key, (byte) 0);
            Arrays.fill(this.buffer, (byte) 0);
        }
    }

    public void clearSalt() {
        if (this.salt != null) {
            Arrays.fill(this.salt, (byte) 0);
        }
    }
}
