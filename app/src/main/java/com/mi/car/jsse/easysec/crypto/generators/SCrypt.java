package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.PBEParametersGenerator;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Pack;

public class SCrypt {
    private SCrypt() {
    }

    public static byte[] generate(byte[] P, byte[] S, int N, int r, int p, int dkLen) {
        if (P == null) {
            throw new IllegalArgumentException("Passphrase P must be provided.");
        } else if (S == null) {
            throw new IllegalArgumentException("Salt S must be provided.");
        } else if (N <= 1 || !isPowerOf2(N)) {
            throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2");
        } else if (r == 1 && N >= 65536) {
            throw new IllegalArgumentException("Cost parameter N must be > 1 and < 65536.");
        } else if (r < 1) {
            throw new IllegalArgumentException("Block size r must be >= 1.");
        } else {
            int maxParallel = Integer.MAX_VALUE / ((r * 128) * 8);
            if (p < 1 || p > maxParallel) {
                throw new IllegalArgumentException("Parallelisation parameter p must be >= 1 and <= " + maxParallel + " (based on block size r of " + r + ")");
            } else if (dkLen >= 1) {
                return MFcrypt(P, S, N, r, p, dkLen);
            } else {
                throw new IllegalArgumentException("Generated key length dkLen must be >= 1.");
            }
        }
    }

    private static byte[] MFcrypt(byte[] P, byte[] S, int N, int r, int p, int dkLen) {
        int MFLenBytes = r * 128;
        byte[] bytes = SingleIterationPBKDF2(P, S, p * MFLenBytes);
        int[] B = null;
        try {
            int BLen = bytes.length >>> 2;
            B = new int[BLen];
            Pack.littleEndianToInt(bytes, 0, B);
            int d = 0;
            int total = N * r;
            while (N - d > 2 && total > 1024) {
                d++;
                total >>>= 1;
            }
            int MFLenWords = MFLenBytes >>> 2;
            for (int BOff = 0; BOff < BLen; BOff += MFLenWords) {
                SMix(B, BOff, N, d, r);
            }
            Pack.intToLittleEndian(B, bytes, 0);
            return SingleIterationPBKDF2(P, bytes, dkLen);
        } finally {
            Clear(bytes);
            Clear(B);
        }
    }

    private static byte[] SingleIterationPBKDF2(byte[] P, byte[] S, int dkLen) {
        PBEParametersGenerator pGen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        pGen.init(P, S, 1);
        return ((KeyParameter) pGen.generateDerivedMacParameters(dkLen * 8)).getKey();
    }

    private static void SMix(int[] B, int BOff, int N, int d, int r) {
        int blocksPerChunk = N >>> d;
        int chunkCount = 1 << d;
        int chunkMask = blocksPerChunk - 1;
        int chunkPow = Integers.numberOfTrailingZeros(N) - d;
        int BCount = r * 32;
        int[] blockX1 = new int[16];
        int[] blockX2 = new int[16];
        int[] blockY = new int[BCount];
        int[] X = new int[BCount];
        int[][] VV = new int[chunkCount][];
        try {
            System.arraycopy(B, BOff, X, 0, BCount);
            for (int c = 0; c < chunkCount; c++) {
                int[] V = new int[(blocksPerChunk * BCount)];
                VV[c] = V;
                int off = 0;
                for (int i = 0; i < blocksPerChunk; i += 2) {
                    System.arraycopy(X, 0, V, off, BCount);
                    int off2 = off + BCount;
                    BlockMix(X, blockX1, blockX2, blockY, r);
                    System.arraycopy(blockY, 0, V, off2, BCount);
                    off = off2 + BCount;
                    BlockMix(blockY, blockX1, blockX2, X, r);
                }
            }
            int mask = N - 1;
            for (int i2 = 0; i2 < N; i2++) {
                int j = X[BCount - 16] & mask;
                System.arraycopy(VV[j >>> chunkPow], (j & chunkMask) * BCount, blockY, 0, BCount);
                Xor(blockY, X, 0, blockY);
                BlockMix(blockY, blockX1, blockX2, X, r);
            }
            System.arraycopy(X, 0, B, BOff, BCount);
            ClearAll(VV);
            ClearAll(new int[][]{X, blockX1, blockX2, blockY});
        } catch (Throwable th) {
            ClearAll(VV);
            ClearAll(new int[][]{X, blockX1, blockX2, blockY});
            throw th;
        }
    }

    private static void BlockMix(int[] B, int[] X1, int[] X2, int[] Y, int r) {
        System.arraycopy(B, B.length - 16, X1, 0, 16);
        int BOff = 0;
        int YOff = 0;
        int halfLen = B.length >>> 1;
        for (int i = r * 2; i > 0; i--) {
            Xor(X1, B, BOff, X2);
            Salsa20Engine.salsaCore(8, X2, X1);
            System.arraycopy(X1, 0, Y, YOff, 16);
            YOff = (halfLen + BOff) - YOff;
            BOff += 16;
        }
    }

    private static void Xor(int[] a, int[] b, int bOff, int[] output) {
        for (int i = output.length - 1; i >= 0; i--) {
            output[i] = a[i] ^ b[bOff + i];
        }
    }

    private static void Clear(byte[] array) {
        if (array != null) {
            Arrays.fill(array, (byte) 0);
        }
    }

    private static void Clear(int[] array) {
        if (array != null) {
            Arrays.fill(array, 0);
        }
    }

    private static void ClearAll(int[][] arrays) {
        for (int[] iArr : arrays) {
            Clear(iArr);
        }
    }

    private static boolean isPowerOf2(int x) {
        return ((x + -1) & x) == 0;
    }
}
