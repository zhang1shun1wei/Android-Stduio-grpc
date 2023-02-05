package com.mi.car.jsse.easysec.pqc.crypto.frodo;

import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.Blake2xsDigest;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;
import java.security.SecureRandom;

class FrodoEngine {
    private static final int nbar = 8;
    private static final int mbar = 8;
    private static final int len_seedA = 128;
    private static final int len_z = 128;
    private static final int len_chi = 16;
    private static final int len_seedA_bytes = 16;
    private static final int len_z_bytes = 16;
    private static final int len_chi_bytes = 2;
    private final int D;
    private final int q;
    private final int n;
    private final int B;
    private final int len_sk_bytes;
    private final int len_pk_bytes;
    private final int len_ct_bytes;
    private final short[] T_chi;
    private final int len_mu;
    private final int len_seedSE;
    private final int len_s;
    private final int len_k;
    private final int len_pkh;
    private final int len_ss;
    private final int len_mu_bytes;
    private final int len_seedSE_bytes;
    private final int len_s_bytes;
    private final int len_k_bytes;
    private final int len_pkh_bytes;
    private final int len_ss_bytes;
    private final Xof digest;
    private final FrodoMatrixGenerator gen;

    public int getCipherTextSize() {
        return this.len_ct_bytes;
    }

    public int getSessionKeySize() {
        return this.len_ss_bytes;
    }

    public int getPrivateKeySize() {
        return this.len_sk_bytes;
    }

    public int getPublicKeySize() {
        return this.len_pk_bytes;
    }

    public FrodoEngine(int n, int D, int B, short[] cdf_table, Xof digest, FrodoMatrixGenerator mGen) {
        this.n = n;
        this.D = D;
        this.q = 1 << D;
        this.B = B;
        this.len_mu = B * 8 * 8;
        this.len_seedSE = this.len_mu;
        this.len_s = this.len_mu;
        this.len_k = this.len_mu;
        this.len_pkh = this.len_mu;
        this.len_ss = this.len_mu;
        this.len_mu_bytes = this.len_mu / 8;
        this.len_seedSE_bytes = this.len_seedSE / 8;
        this.len_s_bytes = this.len_s / 8;
        this.len_k_bytes = this.len_k / 8;
        this.len_pkh_bytes = this.len_pkh / 8;
        this.len_ss_bytes = this.len_ss / 8;
        this.len_ct_bytes = D * n * 8 / 8 + D * 8 * 8 / 8;
        this.len_pk_bytes = 16 + D * n * 8 / 8;
        this.len_sk_bytes = this.len_s_bytes + this.len_pk_bytes + 2 * n * 8 + this.len_pkh_bytes;
        this.T_chi = cdf_table;
        this.digest = digest;
        this.gen = mGen;
    }

    private short sample(short r) {
        short t = (short)((r & '\uffff') >>> 1);
        short e = 0;

        for(int z = 0; z < this.T_chi.length; ++z) {
            if (t > this.T_chi[z]) {
                ++e;
            }
        }

        if ((r & '\uffff') % 2 == 1) {
            e = (short)(e * -1 & '\uffff');
        }

        return e;
    }

    private short[] sample_matrix(short[] r, int offset, int n1, int n2) {
        short[] E = new short[n1 * n2];

        for(int i = 0; i < n1; ++i) {
            for(int j = 0; j < n2; ++j) {
                E[i * n2 + j] = this.sample(r[i * n2 + j + offset]);
            }
        }

        return E;
    }

    private short[] matrix_transpose(short[] X, int n1, int n2) {
        short[] res = new short[n1 * n2];

        for(int i = 0; i < n2; ++i) {
            for(int j = 0; j < n1; ++j) {
                res[i * n1 + j] = X[j * n2 + i];
            }
        }

        return res;
    }

    private short[] matrix_mul(short[] X, int Xrow, int Xcol, short[] Y, int Yrow, int Ycol) {
        short[] res = new short[Xrow * Ycol];

        for(int i = 0; i < Xrow; ++i) {
            for(int j = 0; j < Ycol; ++j) {
                for(int k = 0; k < Xcol; ++k) {
                    res[i * Ycol + j] = (short)((res[i * Ycol + j] & '\uffff') + (X[i * Xcol + k] & '\uffff') * (Y[k * Ycol + j] & '\uffff') & '\uffff');
                }

                res[i * Ycol + j] = (short)((res[i * Ycol + j] & '\uffff') % this.q & '\uffff');
            }
        }

        return res;
    }

    private short[] matrix_add(short[] X, short[] Y, int n1, int m1) {
        short[] res = new short[n1 * m1];

        for(int i = 0; i < n1; ++i) {
            for(int j = 0; j < m1; ++j) {
                res[i * m1 + j] = (short)(((X[i * m1 + j] & '\uffff') + (Y[i * m1 + j] & '\uffff')) % this.q);
            }
        }

        return res;
    }

    private byte[] pack(short[] C) {
        int n = C.length;
        byte[] out = new byte[this.D * n / 8];
        short i = 0;
        short j = 0;
        short w = 0;
        byte bits = 0;

        while(i < out.length && (j < n || j == n && bits > 0)) {
            byte b = 0;

            while(b < 8) {
                int nbits = Math.min(8 - b, bits);
                short mask = (short)((1 << nbits) - 1);
                byte t = (byte)(w >> bits - nbits & mask);
                out[i] = (byte)(out[i] + (t << 8 - b - nbits));
                b = (byte)(b + nbits);
                bits = (byte)(bits - nbits);
                if (bits == 0) {
                    if (j >= n) {
                        break;
                    }

                    w = C[j];
                    bits = (byte)this.D;
                    ++j;
                }
            }

            if (b == 8) {
                ++i;
            }
        }

        return out;
    }

    public void kem_keypair(byte[] pk, byte[] sk, SecureRandom random) {
        byte[] s_seedSE_z = new byte[this.len_s_bytes + this.len_seedSE_bytes + 16];
        random.nextBytes(s_seedSE_z);
        byte[] s = Arrays.copyOfRange(s_seedSE_z, 0, this.len_s_bytes);
        byte[] seedSE = Arrays.copyOfRange(s_seedSE_z, this.len_s_bytes, this.len_s_bytes + this.len_seedSE_bytes);
        byte[] z = Arrays.copyOfRange(s_seedSE_z, this.len_s_bytes + this.len_seedSE_bytes, this.len_s_bytes + this.len_seedSE_bytes + 16);
        byte[] seedA = new byte[16];
        this.digest.update(z, 0, z.length);
        this.digest.doFinal(seedA, 0, seedA.length);
        short[] A = this.gen.genMatrix(seedA);
        byte[] rbytes = new byte[2 * this.n * 8 * 2];
        this.digest.update((byte)95);
        this.digest.update(seedSE, 0, seedSE.length);
        this.digest.doFinal(rbytes, 0, rbytes.length);
        short[] r = new short[2 * this.n * 8];

        for(int i = 0; i < r.length; ++i) {
            r[i] = Pack.littleEndianToShort(rbytes, i * 2);
        }

        short[] S_T = this.sample_matrix(r, 0, 8, this.n);
        short[] S = this.matrix_transpose(S_T, 8, this.n);
        short[] E = this.sample_matrix(r, this.n * 8, this.n, 8);
        short[] B = this.matrix_add(this.matrix_mul(A, this.n, this.n, S, this.n, 8), E, this.n, 8);
        byte[] b = this.pack(B);
        System.arraycopy(Arrays.concatenate(seedA, b), 0, pk, 0, this.len_pk_bytes);
        byte[] pkh = new byte[this.len_pkh_bytes];
        this.digest.update(pk, 0, pk.length);
        this.digest.doFinal(pkh, 0, pkh.length);
        System.arraycopy(Arrays.concatenate(s, pk), 0, sk, 0, this.len_s_bytes + this.len_pk_bytes);

        for(int i = 0; i < 8; ++i) {
            for(int j = 0; j < this.n; ++j) {
                System.arraycopy(Pack.shortToLittleEndian(S_T[i * this.n + j]), 0, sk, this.len_s_bytes + this.len_pk_bytes + i * this.n * 2 + j * 2, 2);
            }
        }

        System.arraycopy(pkh, 0, sk, this.len_sk_bytes - this.len_pkh_bytes, this.len_pkh_bytes);
    }

    private short[] unpack(byte[] in, int n1, int n2) {
        short[] out = new short[n1 * n2];
        short i = 0;
        short j = 0;
        byte w = 0;
        byte bits = 0;

        while(i < out.length && (j < in.length || j == in.length && bits > 0)) {
            byte b = 0;

            while(b < this.D) {
                int nbits = Math.min(this.D - b, bits);
                short mask = (short)((1 << nbits) - 1 & '\uffff');
                byte t = (byte)((w & 255) >>> (bits & 255) - nbits & mask & '\uffff' & 255);
                out[i] = (short)((out[i] & '\uffff') + ((t & 255) << this.D - (b & 255) - nbits) & '\uffff');
                b = (byte)(b + nbits);
                bits = (byte)(bits - nbits);
                w = (byte)(w & ~(mask << bits));
                if (bits == 0) {
                    if (j >= in.length) {
                        break;
                    }

                    w = in[j];
                    bits = 8;
                    ++j;
                }
            }

            if (b == this.D) {
                ++i;
            }
        }

        return out;
    }

    private short[] encode(byte[] k) {
        int byte_index = 0;
        byte mask = 1;
        short[] K = new short[64];

        for(int i = 0; i < 8; ++i) {
            for(int j = 0; j < 8; ++j) {
                int temp = 0;

                for(int l = 0; l < this.B; ++l) {
                    if ((k[byte_index] & mask) == mask) {
                        temp += 1 << l;
                    }

                    mask = (byte)(mask << 1);
                    if (mask == 0) {
                        mask = 1;
                        ++byte_index;
                    }
                }

                K[i * 8 + j] = (short)(temp * (this.q / (1 << this.B)));
            }
        }

        return K;
    }

    public void kem_enc(byte[] ct, byte[] ss, byte[] pk, SecureRandom random) {
        byte[] seedA = Arrays.copyOfRange(pk, 0, 16);
        byte[] b = Arrays.copyOfRange(pk, 16, this.len_pk_bytes);
        byte[] mu = new byte[this.len_mu_bytes];
        random.nextBytes(mu);
        byte[] pkh = new byte[this.len_pkh_bytes];
        this.digest.update(pk, 0, this.len_pk_bytes);
        this.digest.doFinal(pkh, 0, this.len_pkh_bytes);
        byte[] seedSE_k = new byte[this.len_seedSE + this.len_k];
        this.digest.update(pkh, 0, this.len_pkh_bytes);
        this.digest.update(mu, 0, this.len_mu_bytes);
        this.digest.doFinal(seedSE_k, 0, this.len_seedSE_bytes + this.len_k_bytes);
        byte[] seedSE = Arrays.copyOfRange(seedSE_k, 0, this.len_seedSE_bytes);
        byte[] k = Arrays.copyOfRange(seedSE_k, this.len_seedSE_bytes, this.len_seedSE_bytes + this.len_k_bytes);
        byte[] rbytes = new byte[(16 * this.n + 64) * 2];
        this.digest.update((byte)-106);
        this.digest.update(seedSE, 0, seedSE.length);
        this.digest.doFinal(rbytes, 0, rbytes.length);
        short[] r = new short[rbytes.length / 2];

        for(int i = 0; i < r.length; ++i) {
            r[i] = Pack.littleEndianToShort(rbytes, i * 2);
        }

        short[] Sprime = this.sample_matrix(r, 0, 8, this.n);
        short[] Eprime = this.sample_matrix(r, 8 * this.n, 8, this.n);
        short[] A = this.gen.genMatrix(seedA);
        short[] Bprime = this.matrix_add(this.matrix_mul(Sprime, 8, this.n, A, this.n, this.n), Eprime, 8, this.n);
        byte[] c1 = this.pack(Bprime);
        short[] Eprimeprime = this.sample_matrix(r, 16 * this.n, 8, 8);
        short[] B = this.unpack(b, this.n, 8);
        short[] V = this.matrix_add(this.matrix_mul(Sprime, 8, this.n, B, this.n, 8), Eprimeprime, 8, 8);
        short[] EncodedMU = this.encode(mu);
        short[] C = this.matrix_add(V, EncodedMU, 8, 8);
        byte[] c2 = this.pack(C);
        System.arraycopy(Arrays.concatenate(c1, c2), 0, ct, 0, this.len_ct_bytes);
        this.digest.update(c1, 0, c1.length);
        this.digest.update(c2, 0, c2.length);
        this.digest.update(k, 0, this.len_k_bytes);
        this.digest.doFinal(ss, 0, this.len_s_bytes);
    }

    private short[] matrix_sub(short[] X, short[] Y, int n1, int n2) {
        short[] res = new short[n1 * n2];

        for(int i = 0; i < n1; ++i) {
            for(int j = 0; j < n2; ++j) {
                res[i * n2 + j] = (short)((X[i * n2 + j] - Y[i * n2 + j] & '\uffff') % this.q);
            }
        }

        return res;
    }

    private byte[] decode(short[] in) {
        int index = 0;
        int npieces_word = 8;
        int nwords = 8;
        short maskex = (short)((1 << this.B) - 1);
        short maskq = (short)((1 << this.D) - 1);
        byte[] out = new byte[npieces_word * this.B];

        for(int i = 0; i < nwords; ++i) {
            long templong = 0L;

            int j;
            for(j = 0; j < npieces_word; ++j) {
                short temp = (short)((in[index] & maskq) + (1 << this.D - this.B - 1) >> this.D - this.B);
                templong |= (long)(temp & maskex) << this.B * j;
                ++index;
            }

            for(j = 0; j < this.B; ++j) {
                out[i * this.B + j] = (byte)((int)(templong >> 8 * j & 255L));
            }
        }

        return out;
    }

    private short ctverify(short[] a1, short[] a2, short[] b1, short[] b2) {
        short r = 0;

        short i;
        for(i = 0; i < a1.length; ++i) {
            r = (short)(r | a1[i] ^ b1[i]);
        }

        for(i = 0; i < a2.length; ++i) {
            r = (short)(r | a2[i] ^ b2[i]);
        }

        return (short)(r == 0 ? 0 : -1);
    }

    private byte[] ctselect(byte[] a, byte[] b, short selector) {
        byte[] r = new byte[a.length];

        for(int i = 0; i < a.length; ++i) {
            r[i] = (byte)(~selector & a[i] & 255 | selector & b[i] & 255);
        }

        return r;
    }

    public void kem_dec(byte[] ss, byte[] ct, byte[] sk) {
        int offset = 0;
        int length = 8 * this.n * this.D / 8;
        byte[] c1 = Arrays.copyOfRange(ct, offset, offset + length);
        offset = offset + length;
        length = 64 * this.D / 8;
        byte[] c2 = Arrays.copyOfRange(ct, offset, offset + length);
        offset = 0;
        length = this.len_s_bytes;
        byte[] s = Arrays.copyOfRange(sk, offset, offset + length);
        offset = offset + length;
        length = 16;
        byte[] seedA = Arrays.copyOfRange(sk, offset, offset + length);
        offset += length;
        length = this.D * this.n * 8 / 8;
        byte[] b = Arrays.copyOfRange(sk, offset, offset + length);
        offset += length;
        length = this.n * 8 * 16 / 8;
        byte[] Sbytes = Arrays.copyOfRange(sk, offset, offset + length);
        short[] Stransposed = new short[8 * this.n];

        for(int i = 0; i < 8; ++i) {
            for(int j = 0; j < this.n; ++j) {
                Stransposed[i * this.n + j] = Pack.littleEndianToShort(Sbytes, i * this.n * 2 + j * 2);
            }
        }

        short[] S = this.matrix_transpose(Stransposed, 8, this.n);
        offset += length;
        length = this.len_pkh_bytes;
        byte[] pkh = Arrays.copyOfRange(sk, offset, offset + length);
        short[] Bprime = this.unpack(c1, 8, this.n);
        short[] C = this.unpack(c2, 8, 8);
        short[] BprimeS = this.matrix_mul(Bprime, 8, this.n, S, this.n, 8);
        short[] M = this.matrix_sub(C, BprimeS, 8, 8);
        byte[] muprime = this.decode(M);
        byte[] seedSEprime_kprime = new byte[this.len_seedSE_bytes + this.len_k_bytes];
        this.digest.update(pkh, 0, this.len_pkh_bytes);
        this.digest.update(muprime, 0, this.len_mu_bytes);
        this.digest.doFinal(seedSEprime_kprime, 0, this.len_seedSE_bytes + this.len_k_bytes);
        byte[] kprime = Arrays.copyOfRange(seedSEprime_kprime, this.len_seedSE_bytes, this.len_seedSE_bytes + this.len_k_bytes);
        byte[] rbytes = new byte[(16 * this.n + 64) * 2];
        this.digest.update((byte)-106);
        this.digest.update(seedSEprime_kprime, 0, this.len_seedSE_bytes);
        this.digest.doFinal(rbytes, 0, rbytes.length);
        short[] r = new short[16 * this.n + 64];

        for(int i = 0; i < r.length; ++i) {
            r[i] = Pack.littleEndianToShort(rbytes, i * 2);
        }

        short[] Sprime = this.sample_matrix(r, 0, 8, this.n);
        short[] Eprime = this.sample_matrix(r, 8 * this.n, 8, this.n);
        short[] A = this.gen.genMatrix(seedA);
        short[] Bprimeprime = this.matrix_add(this.matrix_mul(Sprime, 8, this.n, A, this.n, this.n), Eprime, 8, this.n);
        short[] Eprimeprime = this.sample_matrix(r, 16 * this.n, 8, 8);
        short[] B = this.unpack(b, this.n, 8);
        short[] V = this.matrix_add(this.matrix_mul(Sprime, 8, this.n, B, this.n, 8), Eprimeprime, 8, 8);
        short[] Cprime = this.matrix_add(V, this.encode(muprime), 8, 8);
        short use_kprime = this.ctverify(Bprime, C, Bprimeprime, Cprime);
        byte[] kbar = this.ctselect(kprime, s, use_kprime);
        this.digest.update(c1, 0, c1.length);
        this.digest.update(c2, 0, c2.length);
        this.digest.update(kbar, 0, kbar.length);
        this.digest.doFinal(ss, 0, this.len_ss_bytes);
    }
}