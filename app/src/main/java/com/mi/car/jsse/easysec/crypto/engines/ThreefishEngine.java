package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.TweakableBlockCipherParameters;

public class ThreefishEngine implements BlockCipher {
    public static final int BLOCKSIZE_1024 = 1024;
    public static final int BLOCKSIZE_256 = 256;
    public static final int BLOCKSIZE_512 = 512;
    private static final long C_240 = 2004413935125273122L;
    private static final int MAX_ROUNDS = 80;
    private static int[] MOD9 = new int[80];
    private static int[] MOD17 = new int[MOD9.length];
    private static int[] MOD3 = new int[MOD9.length];
    private static int[] MOD5 = new int[MOD9.length];
    private static final int ROUNDS_1024 = 80;
    private static final int ROUNDS_256 = 72;
    private static final int ROUNDS_512 = 72;
    private static final int TWEAK_SIZE_BYTES = 16;
    private static final int TWEAK_SIZE_WORDS = 2;
    private int blocksizeBytes;
    private int blocksizeWords;
    private ThreefishCipher cipher;
    private long[] currentBlock;
    private boolean forEncryption;
    private long[] kw;
    private long[] t = new long[5];

    static {
        for (int i = 0; i < MOD9.length; i++) {
            MOD17[i] = i % 17;
            MOD9[i] = i % 9;
            MOD5[i] = i % 5;
            MOD3[i] = i % 3;
        }
    }

    public ThreefishEngine(int blocksizeBits) {
        this.blocksizeBytes = blocksizeBits / 8;
        this.blocksizeWords = this.blocksizeBytes / 8;
        this.currentBlock = new long[this.blocksizeWords];
        this.kw = new long[((this.blocksizeWords * 2) + 1)];
        switch (blocksizeBits) {
            case 256:
                this.cipher = new Threefish256Cipher(this.kw, this.t);
                return;
            case 512:
                this.cipher = new Threefish512Cipher(this.kw, this.t);
                return;
            case 1024:
                this.cipher = new Threefish1024Cipher(this.kw, this.t);
                return;
            default:
                throw new IllegalArgumentException("Invalid blocksize - Threefish is defined with block size of 256, 512, or 1024 bits");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        byte[] keyBytes;
        byte[] tweakBytes;
        if (params instanceof TweakableBlockCipherParameters) {
            TweakableBlockCipherParameters tParams = (TweakableBlockCipherParameters) params;
            keyBytes = tParams.getKey().getKey();
            tweakBytes = tParams.getTweak();
        } else if (params instanceof KeyParameter) {
            keyBytes = ((KeyParameter) params).getKey();
            tweakBytes = null;
        } else {
            throw new IllegalArgumentException("Invalid parameter passed to Threefish init - " + params.getClass().getName());
        }
        long[] keyWords = null;
        long[] tweakWords = null;
        if (keyBytes != null) {
            if (keyBytes.length != this.blocksizeBytes) {
                throw new IllegalArgumentException("Threefish key must be same size as block (" + this.blocksizeBytes + " bytes)");
            }
            keyWords = new long[this.blocksizeWords];
            for (int i = 0; i < keyWords.length; i++) {
                keyWords[i] = bytesToWord(keyBytes, i * 8);
            }
        }
        if (tweakBytes != null) {
            if (tweakBytes.length != 16) {
                throw new IllegalArgumentException("Threefish tweak must be 16 bytes");
            }
            tweakWords = new long[]{bytesToWord(tweakBytes, 0), bytesToWord(tweakBytes, 8)};
        }
        init(forEncryption2, keyWords, tweakWords);
    }

    public void init(boolean forEncryption2, long[] key, long[] tweak) {
        this.forEncryption = forEncryption2;
        if (key != null) {
            setKey(key);
        }
        if (tweak != null) {
            setTweak(tweak);
        }
    }

    private void setKey(long[] key) {
        if (key.length != this.blocksizeWords) {
            throw new IllegalArgumentException("Threefish key must be same size as block (" + this.blocksizeWords + " words)");
        }
        long knw = C_240;
        for (int i = 0; i < this.blocksizeWords; i++) {
            this.kw[i] = key[i];
            knw ^= this.kw[i];
        }
        this.kw[this.blocksizeWords] = knw;
        System.arraycopy(this.kw, 0, this.kw, this.blocksizeWords + 1, this.blocksizeWords);
    }

    private void setTweak(long[] tweak) {
        if (tweak.length != 2) {
            throw new IllegalArgumentException("Tweak must be 2 words.");
        }
        this.t[0] = tweak[0];
        this.t[1] = tweak[1];
        this.t[2] = this.t[0] ^ this.t[1];
        this.t[3] = this.t[0];
        this.t[4] = this.t[1];
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Threefish-" + (this.blocksizeBytes * 8);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.blocksizeBytes;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.blocksizeBytes + inOff > in.length) {
            throw new DataLengthException("Input buffer too short");
        } else if (this.blocksizeBytes + outOff > out.length) {
            throw new OutputLengthException("Output buffer too short");
        } else {
            for (int i = 0; i < this.blocksizeBytes; i += 8) {
                this.currentBlock[i >> 3] = bytesToWord(in, inOff + i);
            }
            processBlock(this.currentBlock, this.currentBlock);
            for (int i2 = 0; i2 < this.blocksizeBytes; i2 += 8) {
                wordToBytes(this.currentBlock[i2 >> 3], out, outOff + i2);
            }
            return this.blocksizeBytes;
        }
    }

    public int processBlock(long[] in, long[] out) throws DataLengthException, IllegalStateException {
        if (this.kw[this.blocksizeWords] == 0) {
            throw new IllegalStateException("Threefish engine not initialised");
        } else if (in.length != this.blocksizeWords) {
            throw new DataLengthException("Input buffer too short");
        } else if (out.length != this.blocksizeWords) {
            throw new OutputLengthException("Output buffer too short");
        } else {
            if (this.forEncryption) {
                this.cipher.encryptBlock(in, out);
            } else {
                this.cipher.decryptBlock(in, out);
            }
            return this.blocksizeWords;
        }
    }

    public static long bytesToWord(byte[] bytes, int off) {
        if (off + 8 > bytes.length) {
            throw new IllegalArgumentException();
        }
        int index = off + 1;
        int index2 = index + 1;
        int index3 = index2 + 1;
        int index4 = index3 + 1;
        int index5 = index4 + 1;
        int index6 = index5 + 1;
        int index7 = index6 + 1;
        int i = index7 + 1;
        return (((long) bytes[off]) & 255) | ((((long) bytes[index]) & 255) << 8) | ((((long) bytes[index2]) & 255) << 16) | ((((long) bytes[index3]) & 255) << 24) | ((((long) bytes[index4]) & 255) << 32) | ((((long) bytes[index5]) & 255) << 40) | ((((long) bytes[index6]) & 255) << 48) | ((((long) bytes[index7]) & 255) << 56);
    }

    public static void wordToBytes(long word, byte[] bytes, int off) {
        if (off + 8 > bytes.length) {
            throw new IllegalArgumentException();
        }
        int index = off + 1;
        bytes[off] = (byte) ((int) word);
        int index2 = index + 1;
        bytes[index] = (byte) ((int) (word >> 8));
        int index3 = index2 + 1;
        bytes[index2] = (byte) ((int) (word >> 16));
        int index4 = index3 + 1;
        bytes[index3] = (byte) ((int) (word >> 24));
        int index5 = index4 + 1;
        bytes[index4] = (byte) ((int) (word >> 32));
        int index6 = index5 + 1;
        bytes[index5] = (byte) ((int) (word >> 40));
        int index7 = index6 + 1;
        bytes[index6] = (byte) ((int) (word >> 48));
        int i = index7 + 1;
        bytes[index7] = (byte) ((int) (word >> 56));
    }

    static long rotlXor(long x, int n, long xor) {
        return ((x << n) | (x >>> (-n))) ^ xor;
    }

    static long xorRotr(long x, int n, long xor) {
        long xored = x ^ xor;
        return (xored >>> n) | (xored << (-n));
    }

    /* access modifiers changed from: private */
    public static abstract class ThreefishCipher {
        protected final long[] kw;
        protected final long[] t;

        /* access modifiers changed from: package-private */
        public abstract void decryptBlock(long[] jArr, long[] jArr2);

        /* access modifiers changed from: package-private */
        public abstract void encryptBlock(long[] jArr, long[] jArr2);

        protected ThreefishCipher(long[] kw2, long[] t2) {
            this.kw = kw2;
            this.t = t2;
        }
    }

    private static final class Threefish256Cipher extends ThreefishCipher {
        private static final int ROTATION_0_0 = 14;
        private static final int ROTATION_0_1 = 16;
        private static final int ROTATION_1_0 = 52;
        private static final int ROTATION_1_1 = 57;
        private static final int ROTATION_2_0 = 23;
        private static final int ROTATION_2_1 = 40;
        private static final int ROTATION_3_0 = 5;
        private static final int ROTATION_3_1 = 37;
        private static final int ROTATION_4_0 = 25;
        private static final int ROTATION_4_1 = 33;
        private static final int ROTATION_5_0 = 46;
        private static final int ROTATION_5_1 = 12;
        private static final int ROTATION_6_0 = 58;
        private static final int ROTATION_6_1 = 22;
        private static final int ROTATION_7_0 = 32;
        private static final int ROTATION_7_1 = 32;

        public Threefish256Cipher(long[] kw, long[] t) {
            super(kw, t);
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.engines.ThreefishEngine.ThreefishCipher
        public void encryptBlock(long[] block, long[] out) {
            long[] kw = this.kw;
            long[] t = this.t;
            int[] mod5 = ThreefishEngine.MOD5;
            int[] mod3 = ThreefishEngine.MOD3;
            if (kw.length != 9) {
                throw new IllegalArgumentException();
            } else if (t.length != 5) {
                throw new IllegalArgumentException();
            } else {
                long b0 = block[0];
                long b1 = block[1];
                long b2 = block[2];
                long b3 = block[3];
                long b02 = b0 + kw[0];
                long b12 = b1 + kw[1] + t[0];
                long b22 = b2 + kw[2] + t[1];
                long b32 = b3 + kw[3];
                for (int d = 1; d < 18; d += 2) {
                    int dm5 = mod5[d];
                    int dm3 = mod3[d];
                    long b03 = b02 + b12;
                    long b13 = ThreefishEngine.rotlXor(b12, 14, b03);
                    long b23 = b22 + b32;
                    long b33 = ThreefishEngine.rotlXor(b32, 16, b23);
                    long b04 = b03 + b33;
                    long b34 = ThreefishEngine.rotlXor(b33, ROTATION_1_0, b04);
                    long b24 = b23 + b13;
                    long b14 = ThreefishEngine.rotlXor(b13, 57, b24);
                    long b05 = b04 + b14;
                    long b15 = ThreefishEngine.rotlXor(b14, 23, b05);
                    long b25 = b24 + b34;
                    long b35 = ThreefishEngine.rotlXor(b34, 40, b25);
                    long b06 = b05 + b35;
                    long b36 = ThreefishEngine.rotlXor(b35, 5, b06);
                    long b26 = b25 + b15;
                    long b16 = ThreefishEngine.rotlXor(b15, ROTATION_3_1, b26);
                    long b07 = b06 + kw[dm5];
                    long b17 = b16 + kw[dm5 + 1] + t[dm3];
                    long b27 = b26 + kw[dm5 + 2] + t[dm3 + 1];
                    long b37 = b36 + kw[dm5 + 3] + ((long) d);
                    long b08 = b07 + b17;
                    long b18 = ThreefishEngine.rotlXor(b17, 25, b08);
                    long b28 = b27 + b37;
                    long b38 = ThreefishEngine.rotlXor(b37, ROTATION_4_1, b28);
                    long b09 = b08 + b38;
                    long b39 = ThreefishEngine.rotlXor(b38, ROTATION_5_0, b09);
                    long b29 = b28 + b18;
                    long b19 = ThreefishEngine.rotlXor(b18, 12, b29);
                    long b010 = b09 + b19;
                    long b110 = ThreefishEngine.rotlXor(b19, ROTATION_6_0, b010);
                    long b210 = b29 + b39;
                    long b310 = ThreefishEngine.rotlXor(b39, 22, b210);
                    long b011 = b010 + b310;
                    long b311 = ThreefishEngine.rotlXor(b310, 32, b011);
                    long b211 = b210 + b110;
                    long b111 = ThreefishEngine.rotlXor(b110, 32, b211);
                    b02 = b011 + kw[dm5 + 1];
                    b12 = b111 + kw[dm5 + 2] + t[dm3 + 1];
                    b22 = b211 + kw[dm5 + 3] + t[dm3 + 2];
                    b32 = b311 + kw[dm5 + 4] + ((long) d) + 1;
                }
                out[0] = b02;
                out[1] = b12;
                out[2] = b22;
                out[3] = b32;
            }
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.engines.ThreefishEngine.ThreefishCipher
        public void decryptBlock(long[] block, long[] state) {
            long[] kw = this.kw;
            long[] t = this.t;
            int[] mod5 = ThreefishEngine.MOD5;
            int[] mod3 = ThreefishEngine.MOD3;
            if (kw.length != 9) {
                throw new IllegalArgumentException();
            } else if (t.length != 5) {
                throw new IllegalArgumentException();
            } else {
                long b0 = block[0];
                long b1 = block[1];
                long b2 = block[2];
                long b3 = block[3];
                for (int d = 17; d >= 1; d -= 2) {
                    int dm5 = mod5[d];
                    int dm3 = mod3[d];
                    long b02 = b0 - kw[dm5 + 1];
                    long b12 = b1 - (kw[dm5 + 2] + t[dm3 + 1]);
                    long b22 = b2 - (kw[dm5 + 3] + t[dm3 + 2]);
                    long b32 = ThreefishEngine.xorRotr(b3 - ((kw[dm5 + 4] + ((long) d)) + 1), 32, b02);
                    long b03 = b02 - b32;
                    long b13 = ThreefishEngine.xorRotr(b12, 32, b22);
                    long b23 = b22 - b13;
                    long b14 = ThreefishEngine.xorRotr(b13, ROTATION_6_0, b03);
                    long b04 = b03 - b14;
                    long b33 = ThreefishEngine.xorRotr(b32, 22, b23);
                    long b24 = b23 - b33;
                    long b34 = ThreefishEngine.xorRotr(b33, ROTATION_5_0, b04);
                    long b05 = b04 - b34;
                    long b15 = ThreefishEngine.xorRotr(b14, 12, b24);
                    long b25 = b24 - b15;
                    long b16 = ThreefishEngine.xorRotr(b15, 25, b05);
                    long b35 = ThreefishEngine.xorRotr(b34, ROTATION_4_1, b25);
                    long b06 = (b05 - b16) - kw[dm5];
                    long b17 = b16 - (kw[dm5 + 1] + t[dm3]);
                    long b26 = (b25 - b35) - (kw[dm5 + 2] + t[dm3 + 1]);
                    long b36 = ThreefishEngine.xorRotr(b35 - (kw[dm5 + 3] + ((long) d)), 5, b06);
                    long b07 = b06 - b36;
                    long b18 = ThreefishEngine.xorRotr(b17, ROTATION_3_1, b26);
                    long b27 = b26 - b18;
                    long b19 = ThreefishEngine.xorRotr(b18, 23, b07);
                    long b08 = b07 - b19;
                    long b37 = ThreefishEngine.xorRotr(b36, 40, b27);
                    long b28 = b27 - b37;
                    long b38 = ThreefishEngine.xorRotr(b37, ROTATION_1_0, b08);
                    long b09 = b08 - b38;
                    long b110 = ThreefishEngine.xorRotr(b19, 57, b28);
                    long b29 = b28 - b110;
                    b1 = ThreefishEngine.xorRotr(b110, 14, b09);
                    b0 = b09 - b1;
                    b3 = ThreefishEngine.xorRotr(b38, 16, b29);
                    b2 = b29 - b3;
                }
                long b010 = b0 - kw[0];
                long b111 = b1 - (kw[1] + t[0]);
                long b210 = b2 - (kw[2] + t[1]);
                state[0] = b010;
                state[1] = b111;
                state[2] = b210;
                state[3] = b3 - kw[3];
            }
        }
    }

    private static final class Threefish512Cipher extends ThreefishCipher {
        private static final int ROTATION_0_0 = 46;
        private static final int ROTATION_0_1 = 36;
        private static final int ROTATION_0_2 = 19;
        private static final int ROTATION_0_3 = 37;
        private static final int ROTATION_1_0 = 33;
        private static final int ROTATION_1_1 = 27;
        private static final int ROTATION_1_2 = 14;
        private static final int ROTATION_1_3 = 42;
        private static final int ROTATION_2_0 = 17;
        private static final int ROTATION_2_1 = 49;
        private static final int ROTATION_2_2 = 36;
        private static final int ROTATION_2_3 = 39;
        private static final int ROTATION_3_0 = 44;
        private static final int ROTATION_3_1 = 9;
        private static final int ROTATION_3_2 = 54;
        private static final int ROTATION_3_3 = 56;
        private static final int ROTATION_4_0 = 39;
        private static final int ROTATION_4_1 = 30;
        private static final int ROTATION_4_2 = 34;
        private static final int ROTATION_4_3 = 24;
        private static final int ROTATION_5_0 = 13;
        private static final int ROTATION_5_1 = 50;
        private static final int ROTATION_5_2 = 10;
        private static final int ROTATION_5_3 = 17;
        private static final int ROTATION_6_0 = 25;
        private static final int ROTATION_6_1 = 29;
        private static final int ROTATION_6_2 = 39;
        private static final int ROTATION_6_3 = 43;
        private static final int ROTATION_7_0 = 8;
        private static final int ROTATION_7_1 = 35;
        private static final int ROTATION_7_2 = 56;
        private static final int ROTATION_7_3 = 22;

        protected Threefish512Cipher(long[] kw, long[] t) {
            super(kw, t);
        }

        @Override // com.mi.car.jsse.easysec.crypto.engines.ThreefishEngine.ThreefishCipher
        public void encryptBlock(long[] block, long[] out) {
            long[] kw = this.kw;
            long[] t = this.t;
            int[] mod9 = ThreefishEngine.MOD9;
            int[] mod3 = ThreefishEngine.MOD3;
            if (kw.length != 17) {
                throw new IllegalArgumentException();
            } else if (t.length != 5) {
                throw new IllegalArgumentException();
            } else {
                long b0 = block[0];
                long b1 = block[1];
                long b2 = block[2];
                long b3 = block[3];
                long b4 = block[4];
                long b5 = block[5];
                long b6 = block[6];
                long b7 = block[7];
                long b02 = b0 + kw[0];
                long b12 = b1 + kw[1];
                long b22 = b2 + kw[2];
                long b32 = b3 + kw[3];
                long b42 = b4 + kw[4];
                long b52 = b5 + kw[5] + t[0];
                long b62 = b6 + kw[6] + t[1];
                long b72 = b7 + kw[7];
                for (int d = 1; d < 18; d += 2) {
                    int dm9 = mod9[d];
                    int dm3 = mod3[d];
                    long b03 = b02 + b12;
                    long b13 = ThreefishEngine.rotlXor(b12, ROTATION_0_0, b03);
                    long b23 = b22 + b32;
                    long b33 = ThreefishEngine.rotlXor(b32, 36, b23);
                    long b43 = b42 + b52;
                    long b53 = ThreefishEngine.rotlXor(b52, 19, b43);
                    long b63 = b62 + b72;
                    long b73 = ThreefishEngine.rotlXor(b72, ROTATION_0_3, b63);
                    long b24 = b23 + b13;
                    long b14 = ThreefishEngine.rotlXor(b13, ROTATION_1_0, b24);
                    long b44 = b43 + b73;
                    long b74 = ThreefishEngine.rotlXor(b73, 27, b44);
                    long b64 = b63 + b53;
                    long b54 = ThreefishEngine.rotlXor(b53, 14, b64);
                    long b04 = b03 + b33;
                    long b34 = ThreefishEngine.rotlXor(b33, ROTATION_1_3, b04);
                    long b45 = b44 + b14;
                    long b15 = ThreefishEngine.rotlXor(b14, 17, b45);
                    long b65 = b64 + b34;
                    long b35 = ThreefishEngine.rotlXor(b34, ROTATION_2_1, b65);
                    long b05 = b04 + b54;
                    long b55 = ThreefishEngine.rotlXor(b54, 36, b05);
                    long b25 = b24 + b74;
                    long b75 = ThreefishEngine.rotlXor(b74, 39, b25);
                    long b66 = b65 + b15;
                    long b16 = ThreefishEngine.rotlXor(b15, ROTATION_3_0, b66);
                    long b06 = b05 + b75;
                    long b76 = ThreefishEngine.rotlXor(b75, 9, b06);
                    long b26 = b25 + b55;
                    long b56 = ThreefishEngine.rotlXor(b55, ROTATION_3_2, b26);
                    long b46 = b45 + b35;
                    long b36 = ThreefishEngine.rotlXor(b35, 56, b46);
                    long b07 = b06 + kw[dm9];
                    long b17 = b16 + kw[dm9 + 1];
                    long b27 = b26 + kw[dm9 + 2];
                    long b37 = b36 + kw[dm9 + 3];
                    long b47 = b46 + kw[dm9 + 4];
                    long b57 = b56 + kw[dm9 + 5] + t[dm3];
                    long b67 = b66 + kw[dm9 + 6] + t[dm3 + 1];
                    long b77 = b76 + kw[dm9 + 7] + ((long) d);
                    long b08 = b07 + b17;
                    long b18 = ThreefishEngine.rotlXor(b17, 39, b08);
                    long b28 = b27 + b37;
                    long b38 = ThreefishEngine.rotlXor(b37, 30, b28);
                    long b48 = b47 + b57;
                    long b58 = ThreefishEngine.rotlXor(b57, ROTATION_4_2, b48);
                    long b68 = b67 + b77;
                    long b78 = ThreefishEngine.rotlXor(b77, 24, b68);
                    long b29 = b28 + b18;
                    long b19 = ThreefishEngine.rotlXor(b18, 13, b29);
                    long b49 = b48 + b78;
                    long b79 = ThreefishEngine.rotlXor(b78, 50, b49);
                    long b69 = b68 + b58;
                    long b59 = ThreefishEngine.rotlXor(b58, 10, b69);
                    long b09 = b08 + b38;
                    long b39 = ThreefishEngine.rotlXor(b38, 17, b09);
                    long b410 = b49 + b19;
                    long b110 = ThreefishEngine.rotlXor(b19, 25, b410);
                    long b610 = b69 + b39;
                    long b310 = ThreefishEngine.rotlXor(b39, 29, b610);
                    long b010 = b09 + b59;
                    long b510 = ThreefishEngine.rotlXor(b59, 39, b010);
                    long b210 = b29 + b79;
                    long b710 = ThreefishEngine.rotlXor(b79, ROTATION_6_3, b210);
                    long b611 = b610 + b110;
                    long b111 = ThreefishEngine.rotlXor(b110, 8, b611);
                    long b011 = b010 + b710;
                    long b711 = ThreefishEngine.rotlXor(b710, ROTATION_7_1, b011);
                    long b211 = b210 + b510;
                    long b511 = ThreefishEngine.rotlXor(b510, 56, b211);
                    long b411 = b410 + b310;
                    long b311 = ThreefishEngine.rotlXor(b310, 22, b411);
                    b02 = b011 + kw[dm9 + 1];
                    b12 = b111 + kw[dm9 + 2];
                    b22 = b211 + kw[dm9 + 3];
                    b32 = b311 + kw[dm9 + 4];
                    b42 = b411 + kw[dm9 + 5];
                    b52 = b511 + kw[dm9 + 6] + t[dm3 + 1];
                    b62 = b611 + kw[dm9 + 7] + t[dm3 + 2];
                    b72 = b711 + kw[dm9 + 8] + ((long) d) + 1;
                }
                out[0] = b02;
                out[1] = b12;
                out[2] = b22;
                out[3] = b32;
                out[4] = b42;
                out[5] = b52;
                out[6] = b62;
                out[7] = b72;
            }
        }

        @Override // com.mi.car.jsse.easysec.crypto.engines.ThreefishEngine.ThreefishCipher
        public void decryptBlock(long[] block, long[] state) {
            long[] kw = this.kw;
            long[] t = this.t;
            int[] mod9 = ThreefishEngine.MOD9;
            int[] mod3 = ThreefishEngine.MOD3;
            if (kw.length != 17) {
                throw new IllegalArgumentException();
            } else if (t.length != 5) {
                throw new IllegalArgumentException();
            } else {
                long b0 = block[0];
                long b1 = block[1];
                long b2 = block[2];
                long b3 = block[3];
                long b4 = block[4];
                long b5 = block[5];
                long b6 = block[6];
                long b7 = block[7];
                for (int d = 17; d >= 1; d -= 2) {
                    int dm9 = mod9[d];
                    int dm3 = mod3[d];
                    long b02 = b0 - kw[dm9 + 1];
                    long b12 = b1 - kw[dm9 + 2];
                    long b22 = b2 - kw[dm9 + 3];
                    long b32 = b3 - kw[dm9 + 4];
                    long b42 = b4 - kw[dm9 + 5];
                    long b52 = b5 - (kw[dm9 + 6] + t[dm3 + 1]);
                    long b62 = b6 - (kw[dm9 + 7] + t[dm3 + 2]);
                    long b13 = ThreefishEngine.xorRotr(b12, 8, b62);
                    long b63 = b62 - b13;
                    long b72 = ThreefishEngine.xorRotr(b7 - ((kw[dm9 + 8] + ((long) d)) + 1), ROTATION_7_1, b02);
                    long b03 = b02 - b72;
                    long b53 = ThreefishEngine.xorRotr(b52, 56, b22);
                    long b23 = b22 - b53;
                    long b33 = ThreefishEngine.xorRotr(b32, 22, b42);
                    long b43 = b42 - b33;
                    long b14 = ThreefishEngine.xorRotr(b13, 25, b43);
                    long b44 = b43 - b14;
                    long b34 = ThreefishEngine.xorRotr(b33, 29, b63);
                    long b64 = b63 - b34;
                    long b54 = ThreefishEngine.xorRotr(b53, 39, b03);
                    long b04 = b03 - b54;
                    long b73 = ThreefishEngine.xorRotr(b72, ROTATION_6_3, b23);
                    long b24 = b23 - b73;
                    long b15 = ThreefishEngine.xorRotr(b14, 13, b24);
                    long b25 = b24 - b15;
                    long b74 = ThreefishEngine.xorRotr(b73, 50, b44);
                    long b45 = b44 - b74;
                    long b55 = ThreefishEngine.xorRotr(b54, 10, b64);
                    long b65 = b64 - b55;
                    long b35 = ThreefishEngine.xorRotr(b34, 17, b04);
                    long b05 = b04 - b35;
                    long b16 = ThreefishEngine.xorRotr(b15, 39, b05);
                    long b36 = ThreefishEngine.xorRotr(b35, 30, b25);
                    long b56 = ThreefishEngine.xorRotr(b55, ROTATION_4_2, b45);
                    long b75 = ThreefishEngine.xorRotr(b74, 24, b65);
                    long b06 = (b05 - b16) - kw[dm9];
                    long b17 = b16 - kw[dm9 + 1];
                    long b26 = (b25 - b36) - kw[dm9 + 2];
                    long b37 = b36 - kw[dm9 + 3];
                    long b46 = (b45 - b56) - kw[dm9 + 4];
                    long b57 = b56 - (kw[dm9 + 5] + t[dm3]);
                    long b66 = (b65 - b75) - (kw[dm9 + 6] + t[dm3 + 1]);
                    long b18 = ThreefishEngine.xorRotr(b17, ROTATION_3_0, b66);
                    long b67 = b66 - b18;
                    long b76 = ThreefishEngine.xorRotr(b75 - (kw[dm9 + 7] + ((long) d)), 9, b06);
                    long b07 = b06 - b76;
                    long b58 = ThreefishEngine.xorRotr(b57, ROTATION_3_2, b26);
                    long b27 = b26 - b58;
                    long b38 = ThreefishEngine.xorRotr(b37, 56, b46);
                    long b47 = b46 - b38;
                    long b19 = ThreefishEngine.xorRotr(b18, 17, b47);
                    long b48 = b47 - b19;
                    long b39 = ThreefishEngine.xorRotr(b38, ROTATION_2_1, b67);
                    long b68 = b67 - b39;
                    long b59 = ThreefishEngine.xorRotr(b58, 36, b07);
                    long b08 = b07 - b59;
                    long b77 = ThreefishEngine.xorRotr(b76, 39, b27);
                    long b28 = b27 - b77;
                    long b110 = ThreefishEngine.xorRotr(b19, ROTATION_1_0, b28);
                    long b29 = b28 - b110;
                    long b78 = ThreefishEngine.xorRotr(b77, 27, b48);
                    long b49 = b48 - b78;
                    long b510 = ThreefishEngine.xorRotr(b59, 14, b68);
                    long b69 = b68 - b510;
                    long b310 = ThreefishEngine.xorRotr(b39, ROTATION_1_3, b08);
                    long b09 = b08 - b310;
                    b1 = ThreefishEngine.xorRotr(b110, ROTATION_0_0, b09);
                    b0 = b09 - b1;
                    b3 = ThreefishEngine.xorRotr(b310, 36, b29);
                    b2 = b29 - b3;
                    b5 = ThreefishEngine.xorRotr(b510, 19, b49);
                    b4 = b49 - b5;
                    b7 = ThreefishEngine.xorRotr(b78, ROTATION_0_3, b69);
                    b6 = b69 - b7;
                }
                long b010 = b0 - kw[0];
                long b111 = b1 - kw[1];
                long b210 = b2 - kw[2];
                long b311 = b3 - kw[3];
                long b410 = b4 - kw[4];
                long b511 = b5 - (kw[5] + t[0]);
                long b610 = b6 - (kw[6] + t[1]);
                state[0] = b010;
                state[1] = b111;
                state[2] = b210;
                state[3] = b311;
                state[4] = b410;
                state[5] = b511;
                state[6] = b610;
                state[7] = b7 - kw[7];
            }
        }
    }

    private static final class Threefish1024Cipher extends ThreefishCipher {
        private static final int ROTATION_0_0 = 24;
        private static final int ROTATION_0_1 = 13;
        private static final int ROTATION_0_2 = 8;
        private static final int ROTATION_0_3 = 47;
        private static final int ROTATION_0_4 = 8;
        private static final int ROTATION_0_5 = 17;
        private static final int ROTATION_0_6 = 22;
        private static final int ROTATION_0_7 = 37;
        private static final int ROTATION_1_0 = 38;
        private static final int ROTATION_1_1 = 19;
        private static final int ROTATION_1_2 = 10;
        private static final int ROTATION_1_3 = 55;
        private static final int ROTATION_1_4 = 49;
        private static final int ROTATION_1_5 = 18;
        private static final int ROTATION_1_6 = 23;
        private static final int ROTATION_1_7 = 52;
        private static final int ROTATION_2_0 = 33;
        private static final int ROTATION_2_1 = 4;
        private static final int ROTATION_2_2 = 51;
        private static final int ROTATION_2_3 = 13;
        private static final int ROTATION_2_4 = 34;
        private static final int ROTATION_2_5 = 41;
        private static final int ROTATION_2_6 = 59;
        private static final int ROTATION_2_7 = 17;
        private static final int ROTATION_3_0 = 5;
        private static final int ROTATION_3_1 = 20;
        private static final int ROTATION_3_2 = 48;
        private static final int ROTATION_3_3 = 41;
        private static final int ROTATION_3_4 = 47;
        private static final int ROTATION_3_5 = 28;
        private static final int ROTATION_3_6 = 16;
        private static final int ROTATION_3_7 = 25;
        private static final int ROTATION_4_0 = 41;
        private static final int ROTATION_4_1 = 9;
        private static final int ROTATION_4_2 = 37;
        private static final int ROTATION_4_3 = 31;
        private static final int ROTATION_4_4 = 12;
        private static final int ROTATION_4_5 = 47;
        private static final int ROTATION_4_6 = 44;
        private static final int ROTATION_4_7 = 30;
        private static final int ROTATION_5_0 = 16;
        private static final int ROTATION_5_1 = 34;
        private static final int ROTATION_5_2 = 56;
        private static final int ROTATION_5_3 = 51;
        private static final int ROTATION_5_4 = 4;
        private static final int ROTATION_5_5 = 53;
        private static final int ROTATION_5_6 = 42;
        private static final int ROTATION_5_7 = 41;
        private static final int ROTATION_6_0 = 31;
        private static final int ROTATION_6_1 = 44;
        private static final int ROTATION_6_2 = 47;
        private static final int ROTATION_6_3 = 46;
        private static final int ROTATION_6_4 = 19;
        private static final int ROTATION_6_5 = 42;
        private static final int ROTATION_6_6 = 44;
        private static final int ROTATION_6_7 = 25;
        private static final int ROTATION_7_0 = 9;
        private static final int ROTATION_7_1 = 48;
        private static final int ROTATION_7_2 = 35;
        private static final int ROTATION_7_3 = 52;
        private static final int ROTATION_7_4 = 23;
        private static final int ROTATION_7_5 = 31;
        private static final int ROTATION_7_6 = 37;
        private static final int ROTATION_7_7 = 20;

        public Threefish1024Cipher(long[] kw, long[] t) {
            super(kw, t);
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.engines.ThreefishEngine.ThreefishCipher
        public void encryptBlock(long[] block, long[] out) {
            long[] kw = this.kw;
            long[] t = this.t;
            int[] mod17 = ThreefishEngine.MOD17;
            int[] mod3 = ThreefishEngine.MOD3;
            if (kw.length != ROTATION_2_0) {
                throw new IllegalArgumentException();
            } else if (t.length != 5) {
                throw new IllegalArgumentException();
            } else {
                long b0 = block[0];
                long b1 = block[1];
                long b2 = block[2];
                long b3 = block[3];
                long b4 = block[4];
                long b5 = block[5];
                long b6 = block[6];
                long b7 = block[7];
                long b8 = block[8];
                long b9 = block[9];
                long b10 = block[10];
                long b11 = block[11];
                long b12 = block[12];
                long b13 = block[13];
                long b14 = block[14];
                long b15 = block[15];
                long b02 = b0 + kw[0];
                long b16 = b1 + kw[1];
                long b22 = b2 + kw[2];
                long b32 = b3 + kw[3];
                long b42 = b4 + kw[4];
                long b52 = b5 + kw[5];
                long b62 = b6 + kw[6];
                long b72 = b7 + kw[7];
                long b82 = b8 + kw[8];
                long b92 = b9 + kw[9];
                long b102 = b10 + kw[10];
                long b112 = b11 + kw[11];
                long b122 = b12 + kw[12];
                long b132 = b13 + kw[13] + t[0];
                long b142 = b14 + kw[14] + t[1];
                long b152 = b15 + kw[15];
                for (int d = 1; d < 20; d += 2) {
                    int dm17 = mod17[d];
                    int dm3 = mod3[d];
                    long b03 = b02 + b16;
                    long b17 = ThreefishEngine.rotlXor(b16, 24, b03);
                    long b23 = b22 + b32;
                    long b33 = ThreefishEngine.rotlXor(b32, 13, b23);
                    long b43 = b42 + b52;
                    long b53 = ThreefishEngine.rotlXor(b52, 8, b43);
                    long b63 = b62 + b72;
                    long b73 = ThreefishEngine.rotlXor(b72, 47, b63);
                    long b83 = b82 + b92;
                    long b93 = ThreefishEngine.rotlXor(b92, 8, b83);
                    long b103 = b102 + b112;
                    long b113 = ThreefishEngine.rotlXor(b112, 17, b103);
                    long b123 = b122 + b132;
                    long b133 = ThreefishEngine.rotlXor(b132, 22, b123);
                    long b143 = b142 + b152;
                    long b153 = ThreefishEngine.rotlXor(b152, 37, b143);
                    long b04 = b03 + b93;
                    long b94 = ThreefishEngine.rotlXor(b93, ROTATION_1_0, b04);
                    long b24 = b23 + b133;
                    long b134 = ThreefishEngine.rotlXor(b133, 19, b24);
                    long b64 = b63 + b113;
                    long b114 = ThreefishEngine.rotlXor(b113, 10, b64);
                    long b44 = b43 + b153;
                    long b154 = ThreefishEngine.rotlXor(b153, ROTATION_1_3, b44);
                    long b104 = b103 + b73;
                    long b74 = ThreefishEngine.rotlXor(b73, ROTATION_1_4, b104);
                    long b124 = b123 + b33;
                    long b34 = ThreefishEngine.rotlXor(b33, 18, b124);
                    long b144 = b143 + b53;
                    long b54 = ThreefishEngine.rotlXor(b53, 23, b144);
                    long b84 = b83 + b17;
                    long b18 = ThreefishEngine.rotlXor(b17, 52, b84);
                    long b05 = b04 + b74;
                    long b75 = ThreefishEngine.rotlXor(b74, ROTATION_2_0, b05);
                    long b25 = b24 + b54;
                    long b55 = ThreefishEngine.rotlXor(b54, 4, b25);
                    long b45 = b44 + b34;
                    long b35 = ThreefishEngine.rotlXor(b34, 51, b45);
                    long b65 = b64 + b18;
                    long b19 = ThreefishEngine.rotlXor(b18, 13, b65);
                    long b125 = b124 + b154;
                    long b155 = ThreefishEngine.rotlXor(b154, 34, b125);
                    long b145 = b144 + b134;
                    long b135 = ThreefishEngine.rotlXor(b134, 41, b145);
                    long b85 = b84 + b114;
                    long b115 = ThreefishEngine.rotlXor(b114, ROTATION_2_6, b85);
                    long b105 = b104 + b94;
                    long b95 = ThreefishEngine.rotlXor(b94, 17, b105);
                    long b06 = b05 + b155;
                    long b156 = ThreefishEngine.rotlXor(b155, 5, b06);
                    long b26 = b25 + b115;
                    long b116 = ThreefishEngine.rotlXor(b115, 20, b26);
                    long b66 = b65 + b135;
                    long b136 = ThreefishEngine.rotlXor(b135, 48, b66);
                    long b46 = b45 + b95;
                    long b96 = ThreefishEngine.rotlXor(b95, 41, b46);
                    long b146 = b145 + b19;
                    long b110 = ThreefishEngine.rotlXor(b19, 47, b146);
                    long b86 = b85 + b55;
                    long b56 = ThreefishEngine.rotlXor(b55, 28, b86);
                    long b106 = b105 + b35;
                    long b36 = ThreefishEngine.rotlXor(b35, 16, b106);
                    long b126 = b125 + b75;
                    long b76 = ThreefishEngine.rotlXor(b75, 25, b126);
                    long b07 = b06 + kw[dm17];
                    long b111 = b110 + kw[dm17 + 1];
                    long b27 = b26 + kw[dm17 + 2];
                    long b37 = b36 + kw[dm17 + 3];
                    long b47 = b46 + kw[dm17 + 4];
                    long b57 = b56 + kw[dm17 + 5];
                    long b67 = b66 + kw[dm17 + 6];
                    long b77 = b76 + kw[dm17 + 7];
                    long b87 = b86 + kw[dm17 + 8];
                    long b97 = b96 + kw[dm17 + 9];
                    long b107 = b106 + kw[dm17 + 10];
                    long b117 = b116 + kw[dm17 + 11];
                    long b127 = b126 + kw[dm17 + 12];
                    long b137 = b136 + kw[dm17 + 13] + t[dm3];
                    long b147 = b146 + kw[dm17 + 14] + t[dm3 + 1];
                    long b157 = b156 + kw[dm17 + 15] + ((long) d);
                    long b08 = b07 + b111;
                    long b118 = ThreefishEngine.rotlXor(b111, 41, b08);
                    long b28 = b27 + b37;
                    long b38 = ThreefishEngine.rotlXor(b37, 9, b28);
                    long b48 = b47 + b57;
                    long b58 = ThreefishEngine.rotlXor(b57, 37, b48);
                    long b68 = b67 + b77;
                    long b78 = ThreefishEngine.rotlXor(b77, 31, b68);
                    long b88 = b87 + b97;
                    long b98 = ThreefishEngine.rotlXor(b97, 12, b88);
                    long b108 = b107 + b117;
                    long b119 = ThreefishEngine.rotlXor(b117, 47, b108);
                    long b128 = b127 + b137;
                    long b138 = ThreefishEngine.rotlXor(b137, 44, b128);
                    long b148 = b147 + b157;
                    long b158 = ThreefishEngine.rotlXor(b157, 30, b148);
                    long b09 = b08 + b98;
                    long b99 = ThreefishEngine.rotlXor(b98, 16, b09);
                    long b29 = b28 + b138;
                    long b139 = ThreefishEngine.rotlXor(b138, 34, b29);
                    long b69 = b68 + b119;
                    long b1110 = ThreefishEngine.rotlXor(b119, 56, b69);
                    long b49 = b48 + b158;
                    long b159 = ThreefishEngine.rotlXor(b158, 51, b49);
                    long b109 = b108 + b78;
                    long b79 = ThreefishEngine.rotlXor(b78, 4, b109);
                    long b129 = b128 + b38;
                    long b39 = ThreefishEngine.rotlXor(b38, ROTATION_5_5, b129);
                    long b149 = b148 + b58;
                    long b59 = ThreefishEngine.rotlXor(b58, 42, b149);
                    long b89 = b88 + b118;
                    long b120 = ThreefishEngine.rotlXor(b118, 41, b89);
                    long b010 = b09 + b79;
                    long b710 = ThreefishEngine.rotlXor(b79, 31, b010);
                    long b210 = b29 + b59;
                    long b510 = ThreefishEngine.rotlXor(b59, 44, b210);
                    long b410 = b49 + b39;
                    long b310 = ThreefishEngine.rotlXor(b39, 47, b410);
                    long b610 = b69 + b120;
                    long b121 = ThreefishEngine.rotlXor(b120, ROTATION_6_3, b610);
                    long b1210 = b129 + b159;
                    long b1510 = ThreefishEngine.rotlXor(b159, 19, b1210);
                    long b1410 = b149 + b139;
                    long b1310 = ThreefishEngine.rotlXor(b139, 42, b1410);
                    long b810 = b89 + b1110;
                    long b1111 = ThreefishEngine.rotlXor(b1110, 44, b810);
                    long b1010 = b109 + b99;
                    long b910 = ThreefishEngine.rotlXor(b99, 25, b1010);
                    long b011 = b010 + b1510;
                    long b1511 = ThreefishEngine.rotlXor(b1510, 9, b011);
                    long b211 = b210 + b1111;
                    long b1112 = ThreefishEngine.rotlXor(b1111, 48, b211);
                    long b611 = b610 + b1310;
                    long b1311 = ThreefishEngine.rotlXor(b1310, ROTATION_7_2, b611);
                    long b411 = b410 + b910;
                    long b911 = ThreefishEngine.rotlXor(b910, 52, b411);
                    long b1411 = b1410 + b121;
                    long b130 = ThreefishEngine.rotlXor(b121, 23, b1411);
                    long b811 = b810 + b510;
                    long b511 = ThreefishEngine.rotlXor(b510, 31, b811);
                    long b1011 = b1010 + b310;
                    long b311 = ThreefishEngine.rotlXor(b310, 37, b1011);
                    long b1211 = b1210 + b710;
                    long b711 = ThreefishEngine.rotlXor(b710, 20, b1211);
                    b02 = b011 + kw[dm17 + 1];
                    b16 = b130 + kw[dm17 + 2];
                    b22 = b211 + kw[dm17 + 3];
                    b32 = b311 + kw[dm17 + 4];
                    b42 = b411 + kw[dm17 + 5];
                    b52 = b511 + kw[dm17 + 6];
                    b62 = b611 + kw[dm17 + 7];
                    b72 = b711 + kw[dm17 + 8];
                    b82 = b811 + kw[dm17 + 9];
                    b92 = b911 + kw[dm17 + 10];
                    b102 = b1011 + kw[dm17 + 11];
                    b112 = b1112 + kw[dm17 + 12];
                    b122 = b1211 + kw[dm17 + 13];
                    b132 = b1311 + kw[dm17 + 14] + t[dm3 + 1];
                    b142 = b1411 + kw[dm17 + 15] + t[dm3 + 2];
                    b152 = b1511 + kw[dm17 + 16] + ((long) d) + 1;
                }
                out[0] = b02;
                out[1] = b16;
                out[2] = b22;
                out[3] = b32;
                out[4] = b42;
                out[5] = b52;
                out[6] = b62;
                out[7] = b72;
                out[8] = b82;
                out[9] = b92;
                out[10] = b102;
                out[11] = b112;
                out[12] = b122;
                out[13] = b132;
                out[14] = b142;
                out[15] = b152;
            }
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.engines.ThreefishEngine.ThreefishCipher
        public void decryptBlock(long[] block, long[] state) {
            long[] kw = this.kw;
            long[] t = this.t;
            int[] mod17 = ThreefishEngine.MOD17;
            int[] mod3 = ThreefishEngine.MOD3;
            if (kw.length != ROTATION_2_0) {
                throw new IllegalArgumentException();
            } else if (t.length != 5) {
                throw new IllegalArgumentException();
            } else {
                long b0 = block[0];
                long b1 = block[1];
                long b2 = block[2];
                long b3 = block[3];
                long b4 = block[4];
                long b5 = block[5];
                long b6 = block[6];
                long b7 = block[7];
                long b8 = block[8];
                long b9 = block[9];
                long b10 = block[10];
                long b11 = block[11];
                long b12 = block[12];
                long b13 = block[13];
                long b14 = block[14];
                long b15 = block[15];
                for (int d = 19; d >= 1; d -= 2) {
                    int dm17 = mod17[d];
                    int dm3 = mod3[d];
                    long b02 = b0 - kw[dm17 + 1];
                    long b16 = b1 - kw[dm17 + 2];
                    long b22 = b2 - kw[dm17 + 3];
                    long b32 = b3 - kw[dm17 + 4];
                    long b42 = b4 - kw[dm17 + 5];
                    long b52 = b5 - kw[dm17 + 6];
                    long b62 = b6 - kw[dm17 + 7];
                    long b72 = b7 - kw[dm17 + 8];
                    long b82 = b8 - kw[dm17 + 9];
                    long b92 = b9 - kw[dm17 + 10];
                    long b102 = b10 - kw[dm17 + 11];
                    long b112 = b11 - kw[dm17 + 12];
                    long b122 = b12 - kw[dm17 + 13];
                    long b132 = b13 - (kw[dm17 + 14] + t[dm3 + 1]);
                    long b142 = b14 - (kw[dm17 + 15] + t[dm3 + 2]);
                    long b152 = ThreefishEngine.xorRotr(b15 - ((kw[dm17 + 16] + ((long) d)) + 1), 9, b02);
                    long b03 = b02 - b152;
                    long b113 = ThreefishEngine.xorRotr(b112, 48, b22);
                    long b23 = b22 - b113;
                    long b133 = ThreefishEngine.xorRotr(b132, ROTATION_7_2, b62);
                    long b63 = b62 - b133;
                    long b93 = ThreefishEngine.xorRotr(b92, 52, b42);
                    long b43 = b42 - b93;
                    long b17 = ThreefishEngine.xorRotr(b16, 23, b142);
                    long b143 = b142 - b17;
                    long b53 = ThreefishEngine.xorRotr(b52, 31, b82);
                    long b83 = b82 - b53;
                    long b33 = ThreefishEngine.xorRotr(b32, 37, b102);
                    long b103 = b102 - b33;
                    long b73 = ThreefishEngine.xorRotr(b72, 20, b122);
                    long b123 = b122 - b73;
                    long b74 = ThreefishEngine.xorRotr(b73, 31, b03);
                    long b04 = b03 - b74;
                    long b54 = ThreefishEngine.xorRotr(b53, 44, b23);
                    long b24 = b23 - b54;
                    long b34 = ThreefishEngine.xorRotr(b33, 47, b43);
                    long b44 = b43 - b34;
                    long b18 = ThreefishEngine.xorRotr(b17, ROTATION_6_3, b63);
                    long b64 = b63 - b18;
                    long b153 = ThreefishEngine.xorRotr(b152, 19, b123);
                    long b124 = b123 - b153;
                    long b134 = ThreefishEngine.xorRotr(b133, 42, b143);
                    long b144 = b143 - b134;
                    long b114 = ThreefishEngine.xorRotr(b113, 44, b83);
                    long b84 = b83 - b114;
                    long b94 = ThreefishEngine.xorRotr(b93, 25, b103);
                    long b104 = b103 - b94;
                    long b95 = ThreefishEngine.xorRotr(b94, 16, b04);
                    long b05 = b04 - b95;
                    long b135 = ThreefishEngine.xorRotr(b134, 34, b24);
                    long b25 = b24 - b135;
                    long b115 = ThreefishEngine.xorRotr(b114, 56, b64);
                    long b65 = b64 - b115;
                    long b154 = ThreefishEngine.xorRotr(b153, 51, b44);
                    long b45 = b44 - b154;
                    long b75 = ThreefishEngine.xorRotr(b74, 4, b104);
                    long b105 = b104 - b75;
                    long b35 = ThreefishEngine.xorRotr(b34, ROTATION_5_5, b124);
                    long b125 = b124 - b35;
                    long b55 = ThreefishEngine.xorRotr(b54, 42, b144);
                    long b145 = b144 - b55;
                    long b19 = ThreefishEngine.xorRotr(b18, 41, b84);
                    long b85 = b84 - b19;
                    long b110 = ThreefishEngine.xorRotr(b19, 41, b05);
                    long b36 = ThreefishEngine.xorRotr(b35, 9, b25);
                    long b56 = ThreefishEngine.xorRotr(b55, 37, b45);
                    long b76 = ThreefishEngine.xorRotr(b75, 31, b65);
                    long b96 = ThreefishEngine.xorRotr(b95, 12, b85);
                    long b116 = ThreefishEngine.xorRotr(b115, 47, b105);
                    long b136 = ThreefishEngine.xorRotr(b135, 44, b125);
                    long b155 = ThreefishEngine.xorRotr(b154, 30, b145);
                    long b06 = (b05 - b110) - kw[dm17];
                    long b111 = b110 - kw[dm17 + 1];
                    long b26 = (b25 - b36) - kw[dm17 + 2];
                    long b37 = b36 - kw[dm17 + 3];
                    long b46 = (b45 - b56) - kw[dm17 + 4];
                    long b57 = b56 - kw[dm17 + 5];
                    long b66 = (b65 - b76) - kw[dm17 + 6];
                    long b77 = b76 - kw[dm17 + 7];
                    long b86 = (b85 - b96) - kw[dm17 + 8];
                    long b97 = b96 - kw[dm17 + 9];
                    long b106 = (b105 - b116) - kw[dm17 + 10];
                    long b117 = b116 - kw[dm17 + 11];
                    long b126 = (b125 - b136) - kw[dm17 + 12];
                    long b137 = b136 - (kw[dm17 + 13] + t[dm3]);
                    long b146 = (b145 - b155) - (kw[dm17 + 14] + t[dm3 + 1]);
                    long b156 = ThreefishEngine.xorRotr(b155 - (kw[dm17 + 15] + ((long) d)), 5, b06);
                    long b07 = b06 - b156;
                    long b118 = ThreefishEngine.xorRotr(b117, 20, b26);
                    long b27 = b26 - b118;
                    long b138 = ThreefishEngine.xorRotr(b137, 48, b66);
                    long b67 = b66 - b138;
                    long b98 = ThreefishEngine.xorRotr(b97, 41, b46);
                    long b47 = b46 - b98;
                    long b119 = ThreefishEngine.xorRotr(b111, 47, b146);
                    long b147 = b146 - b119;
                    long b58 = ThreefishEngine.xorRotr(b57, 28, b86);
                    long b87 = b86 - b58;
                    long b38 = ThreefishEngine.xorRotr(b37, 16, b106);
                    long b107 = b106 - b38;
                    long b78 = ThreefishEngine.xorRotr(b77, 25, b126);
                    long b127 = b126 - b78;
                    long b79 = ThreefishEngine.xorRotr(b78, ROTATION_2_0, b07);
                    long b08 = b07 - b79;
                    long b59 = ThreefishEngine.xorRotr(b58, 4, b27);
                    long b28 = b27 - b59;
                    long b39 = ThreefishEngine.xorRotr(b38, 51, b47);
                    long b48 = b47 - b39;
                    long b120 = ThreefishEngine.xorRotr(b119, 13, b67);
                    long b68 = b67 - b120;
                    long b157 = ThreefishEngine.xorRotr(b156, 34, b127);
                    long b128 = b127 - b157;
                    long b139 = ThreefishEngine.xorRotr(b138, 41, b147);
                    long b148 = b147 - b139;
                    long b1110 = ThreefishEngine.xorRotr(b118, ROTATION_2_6, b87);
                    long b88 = b87 - b1110;
                    long b99 = ThreefishEngine.xorRotr(b98, 17, b107);
                    long b108 = b107 - b99;
                    long b910 = ThreefishEngine.xorRotr(b99, ROTATION_1_0, b08);
                    long b09 = b08 - b910;
                    long b1310 = ThreefishEngine.xorRotr(b139, 19, b28);
                    long b29 = b28 - b1310;
                    long b1111 = ThreefishEngine.xorRotr(b1110, 10, b68);
                    long b69 = b68 - b1111;
                    long b158 = ThreefishEngine.xorRotr(b157, ROTATION_1_3, b48);
                    long b49 = b48 - b158;
                    long b710 = ThreefishEngine.xorRotr(b79, ROTATION_1_4, b108);
                    long b109 = b108 - b710;
                    long b310 = ThreefishEngine.xorRotr(b39, 18, b128);
                    long b129 = b128 - b310;
                    long b510 = ThreefishEngine.xorRotr(b59, 23, b148);
                    long b149 = b148 - b510;
                    long b121 = ThreefishEngine.xorRotr(b120, 52, b88);
                    long b89 = b88 - b121;
                    b1 = ThreefishEngine.xorRotr(b121, 24, b09);
                    b0 = b09 - b1;
                    b3 = ThreefishEngine.xorRotr(b310, 13, b29);
                    b2 = b29 - b3;
                    b5 = ThreefishEngine.xorRotr(b510, 8, b49);
                    b4 = b49 - b5;
                    b7 = ThreefishEngine.xorRotr(b710, 47, b69);
                    b6 = b69 - b7;
                    b9 = ThreefishEngine.xorRotr(b910, 8, b89);
                    b8 = b89 - b9;
                    b11 = ThreefishEngine.xorRotr(b1111, 17, b109);
                    b10 = b109 - b11;
                    b13 = ThreefishEngine.xorRotr(b1310, 22, b129);
                    b12 = b129 - b13;
                    b15 = ThreefishEngine.xorRotr(b158, 37, b149);
                    b14 = b149 - b15;
                }
                long b010 = b0 - kw[0];
                long b130 = b1 - kw[1];
                long b210 = b2 - kw[2];
                long b311 = b3 - kw[3];
                long b410 = b4 - kw[4];
                long b511 = b5 - kw[5];
                long b610 = b6 - kw[6];
                long b711 = b7 - kw[7];
                long b810 = b8 - kw[8];
                long b911 = b9 - kw[9];
                long b1010 = b10 - kw[10];
                long b1112 = b11 - kw[11];
                long b1210 = b12 - kw[12];
                long b1311 = b13 - (kw[13] + t[0]);
                long b1410 = b14 - (kw[14] + t[1]);
                state[0] = b010;
                state[1] = b130;
                state[2] = b210;
                state[3] = b311;
                state[4] = b410;
                state[5] = b511;
                state[6] = b610;
                state[7] = b711;
                state[8] = b810;
                state[9] = b911;
                state[10] = b1010;
                state[11] = b1112;
                state[12] = b1210;
                state[13] = b1311;
                state[14] = b1410;
                state[15] = b15 - kw[15];
            }
        }
    }
}
