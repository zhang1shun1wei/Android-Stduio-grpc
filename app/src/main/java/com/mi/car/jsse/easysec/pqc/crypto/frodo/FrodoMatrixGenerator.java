package com.mi.car.jsse.easysec.pqc.crypto.frodo;

import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.Blake2xsDigest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.crypto.engines.AESEngine;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Exceptions;
import com.mi.car.jsse.easysec.util.Pack;

abstract class FrodoMatrixGenerator {
    int n;
    int q;

    /* access modifiers changed from: package-private */
    public abstract short[] genMatrix(byte[] bArr);

    public FrodoMatrixGenerator(int n2, int q2) {
        this.n = n2;
        this.q = q2;
    }

    static class Shake128MatrixGenerator extends FrodoMatrixGenerator {
        public Shake128MatrixGenerator(int n, int q) {
            super(n, q);
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoMatrixGenerator
        public short[] genMatrix(byte[] seedA) {
            short[] A = new short[(this.n * this.n)];
            byte[] tmp = new byte[((this.n * 16) / 8)];
            for (short i = 0; i < this.n; i = (short) (i + 1)) {
                byte[] b = Arrays.concatenate(Pack.shortToLittleEndian(i), seedA);
                Xof digest = new SHAKEDigest(128);
                digest.update(b, 0, b.length);
                digest.doFinal(tmp, 0, tmp.length);
                for (short j = 0; j < this.n; j = (short) (j + 1)) {
                    A[(this.n * i) + j] = (short) (Pack.littleEndianToShort(tmp, j * 2) % this.q);
                }
            }
            return A;
        }
    }

    static class Aes128MatrixGenerator extends FrodoMatrixGenerator {
        BufferedBlockCipher cipher = new BufferedBlockCipher(new AESEngine());

        public Aes128MatrixGenerator(int n, int q) {
            super(n, q);
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoMatrixGenerator
        public short[] genMatrix(byte[] seedA) {
            short[] A = new short[(this.n * this.n)];
            byte[] b = new byte[16];
            byte[] c = new byte[16];
            for (int i = 0; i < this.n; i++) {
                for (int j = 0; j < this.n; j += 8) {
                    System.arraycopy(Pack.shortToLittleEndian((short) (i & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH)), 0, b, 0, 2);
                    System.arraycopy(Pack.shortToLittleEndian((short) (j & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH)), 0, b, 2, 2);
                    aes128(c, seedA, b);
                    for (int k = 0; k < 8; k++) {
                        A[(this.n * i) + j + k] = (short) (Pack.littleEndianToShort(c, k * 2) % this.q);
                    }
                }
            }
            return A;
        }

        /* access modifiers changed from: package-private */
        public void aes128(byte[] out, byte[] keyBytes, byte[] msg) {
            try {
                this.cipher.init(true, new KeyParameter(keyBytes));
                this.cipher.doFinal(out, this.cipher.processBytes(msg, 0, msg.length, out, 0));
            } catch (InvalidCipherTextException e) {
                throw Exceptions.illegalStateException(e.toString(), e);
            }
        }
    }
}
