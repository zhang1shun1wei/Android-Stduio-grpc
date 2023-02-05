package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.util.Strings;

class HashFunctions {
    private static final byte[] hashc = Strings.toByteArray("expand 32-byte to 64-byte state!");
    private final Digest dig256;
    private final Digest dig512;
    private final Permute perm;

    HashFunctions(Digest dig2562) {
        this(dig2562, null);
    }

    HashFunctions(Digest dig2562, Digest dig5122) {
        this.perm = new Permute();
        this.dig256 = dig2562;
        this.dig512 = dig5122;
    }

    /* access modifiers changed from: package-private */
    public int varlen_hash(byte[] out, int outOff, byte[] in, int inLen) {
        this.dig256.update(in, 0, inLen);
        this.dig256.doFinal(out, outOff);
        return 0;
    }

    /* access modifiers changed from: package-private */
    public Digest getMessageHash() {
        return this.dig512;
    }

    /* access modifiers changed from: package-private */
    public int hash_2n_n(byte[] out, int outOff, byte[] in, int inOff) {
        byte[] x = new byte[64];
        for (int i = 0; i < 32; i++) {
            x[i] = in[inOff + i];
            x[i + 32] = hashc[i];
        }
        this.perm.chacha_permute(x, x);
        for (int i2 = 0; i2 < 32; i2++) {
            x[i2] = (byte) (x[i2] ^ in[(inOff + i2) + 32]);
        }
        this.perm.chacha_permute(x, x);
        for (int i3 = 0; i3 < 32; i3++) {
            out[outOff + i3] = x[i3];
        }
        return 0;
    }

    /* access modifiers changed from: package-private */
    public int hash_2n_n_mask(byte[] out, int outOff, byte[] in, int inOff, byte[] mask, int maskOff) {
        byte[] buf = new byte[64];
        for (int i = 0; i < 64; i++) {
            buf[i] = (byte) (in[inOff + i] ^ mask[maskOff + i]);
        }
        return hash_2n_n(out, outOff, buf, 0);
    }

    /* access modifiers changed from: package-private */
    public int hash_n_n(byte[] out, int outOff, byte[] in, int inOff) {
        byte[] x = new byte[64];
        for (int i = 0; i < 32; i++) {
            x[i] = in[inOff + i];
            x[i + 32] = hashc[i];
        }
        this.perm.chacha_permute(x, x);
        for (int i2 = 0; i2 < 32; i2++) {
            out[outOff + i2] = x[i2];
        }
        return 0;
    }

    /* access modifiers changed from: package-private */
    public int hash_n_n_mask(byte[] out, int outOff, byte[] in, int inOff, byte[] mask, int maskOff) {
        byte[] buf = new byte[32];
        for (int i = 0; i < 32; i++) {
            buf[i] = (byte) (in[inOff + i] ^ mask[maskOff + i]);
        }
        return hash_n_n(out, outOff, buf, 0);
    }
}
