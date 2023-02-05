package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.Blake2xsDigest;
import com.mi.car.jsse.easysec.crypto.digests.SHA3Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.util.Arrays;
import java.lang.reflect.Array;
import java.security.SecureRandom;

/* access modifiers changed from: package-private */
public class SABEREngine {
    public static final int SABER_EP = 10;
    public static final int SABER_EQ = 13;
    private static final int SABER_HASHBYTES = 32;
    private static final int SABER_KEYBYTES = 32;
    public static final int SABER_N = 256;
    private static final int SABER_NOISE_SEEDBYTES = 32;
    private static final int SABER_SEEDBYTES = 32;
    private final int SABER_BYTES_CCA_DEC;
    private final int SABER_ET;
    private final int SABER_INDCPA_PUBLICKEYBYTES;
    private final int SABER_INDCPA_SECRETKEYBYTES;
    private final int SABER_L;
    private final int SABER_MU;
    private final int SABER_POLYBYTES;
    private final int SABER_POLYCOINBYTES;
    private final int SABER_POLYCOMPRESSEDBYTES;
    private final int SABER_POLYVECBYTES;
    private final int SABER_POLYVECCOMPRESSEDBYTES;
    private final int SABER_PUBLICKEYBYTES;
    private final int SABER_SCALEBYTES_KEM;
    private final int SABER_SECRETKEYBYTES;
    private final int defaultKeySize;
    private final int h1;
    private final int h2;
    private final Poly poly;
    private final Utils utils;

    public int getSABER_N() {
        return 256;
    }

    public int getSABER_EP() {
        return 10;
    }

    public int getSABER_KEYBYTES() {
        return 32;
    }

    public int getSABER_L() {
        return this.SABER_L;
    }

    public int getSABER_ET() {
        return this.SABER_ET;
    }

    public int getSABER_POLYBYTES() {
        return this.SABER_POLYBYTES;
    }

    public int getSABER_POLYVECBYTES() {
        return this.SABER_POLYVECBYTES;
    }

    public int getSABER_SEEDBYTES() {
        return 32;
    }

    public int getSABER_POLYCOINBYTES() {
        return this.SABER_POLYCOINBYTES;
    }

    public int getSABER_NOISE_SEEDBYTES() {
        return 32;
    }

    public int getSABER_MU() {
        return this.SABER_MU;
    }

    public Utils getUtils() {
        return this.utils;
    }

    public int getSessionKeySize() {
        return this.defaultKeySize / 8;
    }

    public int getCipherTextSize() {
        return this.SABER_BYTES_CCA_DEC;
    }

    public int getPublicKeySize() {
        return this.SABER_PUBLICKEYBYTES;
    }

    public int getPrivateKeySize() {
        return this.SABER_SECRETKEYBYTES;
    }

    public SABEREngine(int l, int defaultKeySize2) {
        this.defaultKeySize = defaultKeySize2;
        this.SABER_L = l;
        if (l == 2) {
            this.SABER_MU = 10;
            this.SABER_ET = 3;
        } else if (l == 3) {
            this.SABER_MU = 8;
            this.SABER_ET = 4;
        } else {
            this.SABER_MU = 6;
            this.SABER_ET = 6;
        }
        this.SABER_POLYCOINBYTES = (this.SABER_MU * 256) / 8;
        this.SABER_POLYBYTES = 416;
        this.SABER_POLYVECBYTES = this.SABER_L * this.SABER_POLYBYTES;
        this.SABER_POLYCOMPRESSEDBYTES = 320;
        this.SABER_POLYVECCOMPRESSEDBYTES = this.SABER_L * this.SABER_POLYCOMPRESSEDBYTES;
        this.SABER_SCALEBYTES_KEM = (this.SABER_ET * 256) / 8;
        this.SABER_INDCPA_PUBLICKEYBYTES = this.SABER_POLYVECCOMPRESSEDBYTES + 32;
        this.SABER_INDCPA_SECRETKEYBYTES = this.SABER_POLYVECBYTES;
        this.SABER_PUBLICKEYBYTES = this.SABER_INDCPA_PUBLICKEYBYTES;
        this.SABER_SECRETKEYBYTES = this.SABER_INDCPA_SECRETKEYBYTES + this.SABER_INDCPA_PUBLICKEYBYTES + 32 + 32;
        this.SABER_BYTES_CCA_DEC = this.SABER_POLYVECCOMPRESSEDBYTES + this.SABER_SCALEBYTES_KEM;
        this.h1 = 4;
        this.h2 = (256 - (1 << ((10 - this.SABER_ET) - 1))) + 4;
        this.utils = new Utils(this);
        this.poly = new Poly(this);
    }

    private void indcpa_kem_keypair(byte[] pk, byte[] sk, SecureRandom random) {
        short[][][] A = (short[][][]) Array.newInstance(Short.TYPE, this.SABER_L, this.SABER_L, 256);
        short[][] s = (short[][]) Array.newInstance(Short.TYPE, this.SABER_L, 256);
        short[][] b = (short[][]) Array.newInstance(Short.TYPE, this.SABER_L, 256);
        byte[] seed_A = new byte[32];
        byte[] seed_s = new byte[32];
        random.nextBytes(seed_A);
        Xof digest = new SHAKEDigest(128);
        digest.update(seed_A, 0, 32);
        digest.doFinal(seed_A, 0, 32);
        random.nextBytes(seed_s);
        this.poly.GenMatrix(A, seed_A);
        this.poly.GenSecret(s, seed_s);
        this.poly.MatrixVectorMul(A, s, b, 1);
        for (int i = 0; i < this.SABER_L; i++) {
            for (int j = 0; j < 256; j++) {
                b[i][j] = (short) (((b[i][j] + this.h1) & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH) >>> 3);
            }
        }
        this.utils.POLVECq2BS(sk, s);
        this.utils.POLVECp2BS(pk, b);
        System.arraycopy(seed_A, 0, pk, this.SABER_POLYVECCOMPRESSEDBYTES, seed_A.length);
    }

    public int crypto_kem_keypair(byte[] pk, byte[] sk, SecureRandom random) {
        indcpa_kem_keypair(pk, sk, random);
        for (int i = 0; i < this.SABER_INDCPA_PUBLICKEYBYTES; i++) {
            sk[this.SABER_INDCPA_SECRETKEYBYTES + i] = pk[i];
        }
        SHA3Digest digest = new SHA3Digest(256);
        digest.update(pk, 0, this.SABER_INDCPA_PUBLICKEYBYTES);
        digest.doFinal(sk, this.SABER_SECRETKEYBYTES - 64);
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        System.arraycopy(nonce, 0, sk, this.SABER_SECRETKEYBYTES - 32, nonce.length);
        return 0;
    }

    private void indcpa_kem_enc(byte[] m, byte[] seed_sp, byte[] pk, byte[] ciphertext) {
        short[][][] A = (short[][][]) Array.newInstance(Short.TYPE, this.SABER_L, this.SABER_L, 256);
        short[][] sp = (short[][]) Array.newInstance(Short.TYPE, this.SABER_L, 256);
        short[][] bp = (short[][]) Array.newInstance(Short.TYPE, this.SABER_L, 256);
        short[][] b = (short[][]) Array.newInstance(Short.TYPE, this.SABER_L, 256);
        short[] mp = new short[256];
        short[] vp = new short[256];
        this.poly.GenMatrix(A, Arrays.copyOfRange(pk, this.SABER_POLYVECCOMPRESSEDBYTES, pk.length));
        this.poly.GenSecret(sp, seed_sp);
        this.poly.MatrixVectorMul(A, sp, bp, 0);
        for (int i = 0; i < this.SABER_L; i++) {
            for (int j = 0; j < 256; j++) {
                bp[i][j] = (short) (((bp[i][j] + this.h1) & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH) >>> 3);
            }
        }
        this.utils.POLVECp2BS(ciphertext, bp);
        this.utils.BS2POLVECp(pk, b);
        this.poly.InnerProd(b, sp, vp);
        this.utils.BS2POLmsg(m, mp);
        for (int j2 = 0; j2 < 256; j2++) {
            vp[j2] = (short) ((((vp[j2] - (mp[j2] << 9)) + this.h1) & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH) >>> (10 - this.SABER_ET));
        }
        this.utils.POLT2BS(ciphertext, this.SABER_POLYVECCOMPRESSEDBYTES, vp);
    }

    public int crypto_kem_enc(byte[] c, byte[] k, byte[] pk, SecureRandom random) {
        byte[] kr = new byte[64];
        byte[] buf = new byte[64];
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        SHA3Digest digest_256 = new SHA3Digest(256);
        SHA3Digest digest_512 = new SHA3Digest(512);
        digest_256.update(nonce, 0, 32);
        digest_256.doFinal(nonce, 0);
        System.arraycopy(nonce, 0, buf, 0, 32);
        digest_256.update(pk, 0, this.SABER_INDCPA_PUBLICKEYBYTES);
        digest_256.doFinal(buf, 32);
        digest_512.update(buf, 0, 64);
        digest_512.doFinal(kr, 0);
        indcpa_kem_enc(buf, Arrays.copyOfRange(kr, 32, kr.length), pk, c);
        digest_256.update(c, 0, this.SABER_BYTES_CCA_DEC);
        digest_256.doFinal(kr, 32);
        byte[] temp_k = new byte[32];
        digest_256.update(kr, 0, 64);
        digest_256.doFinal(temp_k, 0);
        System.arraycopy(temp_k, 0, k, 0, this.defaultKeySize / 8);
        return 0;
    }

    private void indcpa_kem_dec(byte[] sk, byte[] ciphertext, byte[] m) {
        short[][] s = (short[][]) Array.newInstance(Short.TYPE, this.SABER_L, 256);
        short[][] b = (short[][]) Array.newInstance(Short.TYPE, this.SABER_L, 256);
        short[] v = new short[256];
        short[] cm = new short[256];
        this.utils.BS2POLVECq(sk, 0, s);
        this.utils.BS2POLVECp(ciphertext, b);
        this.poly.InnerProd(b, s, v);
        this.utils.BS2POLT(ciphertext, this.SABER_POLYVECCOMPRESSEDBYTES, cm);
        for (int i = 0; i < 256; i++) {
            v[i] = (short) ((((v[i] + this.h2) - (cm[i] << (10 - this.SABER_ET))) & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH) >> 9);
        }
        this.utils.POLmsg2BS(m, v);
    }

    public int crypto_kem_dec(byte[] k, byte[] c, byte[] sk) {
        byte[] cmp = new byte[this.SABER_BYTES_CCA_DEC];
        byte[] buf = new byte[64];
        byte[] kr = new byte[64];
        byte[] pk = Arrays.copyOfRange(sk, this.SABER_INDCPA_SECRETKEYBYTES, sk.length);
        indcpa_kem_dec(sk, c, buf);
        for (int i = 0; i < 32; i++) {
            buf[i + 32] = sk[(this.SABER_SECRETKEYBYTES - 64) + i];
        }
        SHA3Digest digest_256 = new SHA3Digest(256);
        SHA3Digest digest_512 = new SHA3Digest(512);
        digest_512.update(buf, 0, 64);
        digest_512.doFinal(kr, 0);
        indcpa_kem_enc(buf, Arrays.copyOfRange(kr, 32, kr.length), pk, cmp);
        int fail = verify(c, cmp, this.SABER_BYTES_CCA_DEC);
        digest_256.update(c, 0, this.SABER_BYTES_CCA_DEC);
        digest_256.doFinal(kr, 32);
        cmov(kr, sk, this.SABER_SECRETKEYBYTES - 32, 32, (byte) fail);
        byte[] temp_k = new byte[32];
        digest_256.update(kr, 0, 64);
        digest_256.doFinal(temp_k, 0);
        System.arraycopy(temp_k, 0, k, 0, this.defaultKeySize / 8);
        return 0;
    }

    static int verify(byte[] a, byte[] b, int len) {
        long r = 0;
        for (int i = 0; i < len; i++) {
            r |= (long) (a[i] ^ b[i]);
        }
        return (int) ((-r) >>> 63);
    }

    static void cmov(byte[] r, byte[] x, int x_offset, int len, byte b) {
        byte b2 = (byte) (-b);
        for (int i = 0; i < len; i++) {
            r[i] = (byte) (r[i] ^ ((x[i + x_offset] ^ r[i]) & b2));
        }
    }
}
