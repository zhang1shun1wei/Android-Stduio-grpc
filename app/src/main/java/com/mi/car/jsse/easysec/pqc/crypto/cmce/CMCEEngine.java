package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.Blake2xsDigest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Arrays;
import java.lang.reflect.Array;
import java.security.SecureRandom;

class CMCEEngine {
    private int SYS_N;
    private int SYS_T;
    private int GFBITS;
    private int IRR_BYTES;
    private int COND_BYTES;
    private int PK_NROWS;
    private int PK_NCOLS;
    private int PK_ROW_BYTES;
    private int SYND_BYTES;
    private int GFMASK;
    private int[] poly;
    private final int defaultKeySize;
    private GF gf;
    private BENES benes;
    private boolean usePadding;
    private boolean countErrorIndices;
    private boolean usePivots;

    public int getIrrBytes() {
        return this.IRR_BYTES;
    }

    public int getCondBytes() {
        return this.COND_BYTES;
    }

    public int getPrivateKeySize() {
        return this.COND_BYTES + this.IRR_BYTES + this.SYS_N / 8 + 40;
    }

    public int getPublicKeySize() {
        return this.usePadding ? this.PK_NROWS * (this.SYS_N / 8 - (this.PK_NROWS - 1) / 8) : this.PK_NROWS * this.PK_NCOLS / 8;
    }

    public int getCipherTextSize() {
        return this.SYND_BYTES + 32;
    }

    public CMCEEngine(int m, int n, int t, int[] p, boolean usePivots, int defaultKeySize) {
        this.usePivots = usePivots;
        this.SYS_N = n;
        this.SYS_T = t;
        this.GFBITS = m;
        this.poly = p;
        this.defaultKeySize = defaultKeySize;
        this.IRR_BYTES = this.SYS_T * 2;
        this.COND_BYTES = (1 << this.GFBITS - 4) * (2 * this.GFBITS - 1);
        this.PK_NROWS = this.SYS_T * this.GFBITS;
        this.PK_NCOLS = this.SYS_N - this.PK_NROWS;
        this.PK_ROW_BYTES = (this.PK_NCOLS + 7) / 8;
        this.SYND_BYTES = (this.PK_NROWS + 7) / 8;
        this.GFMASK = (1 << this.GFBITS) - 1;
        if (this.GFBITS == 12) {
            this.gf = new GF12(this.GFBITS);
            this.benes = new BENES12(this.SYS_N, this.SYS_T, this.GFBITS);
        } else {
            this.gf = new GF13(this.GFBITS);
            this.benes = new BENES13(this.SYS_N, this.SYS_T, this.GFBITS);
        }

        this.usePadding = this.SYS_T % 8 != 0;
        this.countErrorIndices = 1 << this.GFBITS > this.SYS_N;
    }

    public byte[] generate_public_key_from_private_key(byte[] sk) {
        byte[] pk = new byte[this.getPublicKeySize()];
        short[] pi = new short[1 << this.GFBITS];
        long[] pivots = new long[]{0L};
        int[] perm = new int[1 << this.GFBITS];
        byte[] hash = new byte[this.SYS_N / 8 + (1 << this.GFBITS) * 4];
        int hash_idx = hash.length - 32 - this.IRR_BYTES - (1 << this.GFBITS) * 4;
        Xof digest = new SHAKEDigest(256);
        digest.update((byte)64);
        digest.update(sk, 0, 32);
        digest.doFinal(hash, 0, hash.length);

        for(int i = 0; i < 1 << this.GFBITS; ++i) {
            perm[i] = Utils.load4(hash, hash_idx + i * 4);
        }

        this.pk_gen(pk, sk, perm, pi, pivots);
        return pk;
    }

    public byte[] decompress_private_key(byte[] sk) {
        byte[] reg_sk = new byte[this.getPrivateKeySize()];
        System.arraycopy(sk, 0, reg_sk, 0, sk.length);
        byte[] hash = new byte[this.SYS_N / 8 + (1 << this.GFBITS) * 4 + this.IRR_BYTES + 32];
        Xof digest = new SHAKEDigest(256);
        digest.update((byte)64);
        digest.update(sk, 0, 32);
        digest.doFinal(hash, 0, hash.length);
        int i;
        int hash_idx;
        if (sk.length <= 40) {
            short[] field = new short[this.SYS_T];
            byte[] reg_g = new byte[this.IRR_BYTES];
            hash_idx = hash.length - 32 - this.IRR_BYTES;

            for(i = 0; i < this.SYS_T; ++i) {
                field[i] = Utils.load_gf(hash, hash_idx + i * 2, this.GFMASK);
            }

            this.generate_irr_poly(field);

            for(i = 0; i < this.SYS_T; ++i) {
                Utils.store_gf(reg_g, i * 2, field[i]);
            }

            System.arraycopy(reg_g, 0, reg_sk, 40, this.IRR_BYTES);
        }

        if (sk.length <= 40 + this.IRR_BYTES) {
            int[] perm = new int[1 << this.GFBITS];
            short[] pi = new short[1 << this.GFBITS];
            hash_idx = hash.length - 32 - this.IRR_BYTES - (1 << this.GFBITS) * 4;

            for(i = 0; i < 1 << this.GFBITS; ++i) {
                perm[i] = Utils.load4(hash, hash_idx + i * 4);
            }

            long[] buf;
            if (this.usePivots) {
                buf = new long[]{0L};
                this.pk_gen((byte[])null, reg_sk, perm, pi, buf);
            } else {
                buf = new long[1 << this.GFBITS];

                for(i = 0; i < 1 << this.GFBITS; ++i) {
                    buf[i] = (long)perm[i];
                    buf[i] <<= 31;
                    buf[i] |= (long)i;
                    buf[i] &= 9223372036854775807L;
                }

                sort64(buf, 0, buf.length);

                for(i = 0; i < 1 << this.GFBITS; ++i) {
                    pi[i] = (short)((int)(buf[i] & (long)this.GFMASK));
                }
            }

            byte[] out = new byte[this.COND_BYTES];
            controlbitsfrompermutation(out, pi, (long)this.GFBITS, (long)(1 << this.GFBITS));
            System.arraycopy(out, 0, reg_sk, this.IRR_BYTES + 40, out.length);
        }

        System.arraycopy(hash, 0, reg_sk, this.getPrivateKeySize() - this.SYS_N / 8, this.SYS_N / 8);
        return reg_sk;
    }

    public void kem_keypair(byte[] pk, byte[] sk, SecureRandom random) {
        byte[] seed_a = new byte[1];
        byte[] seed_b = new byte[32];
        seed_a[0] = 64;
        random.nextBytes(seed_b);
        byte[] E = new byte[this.SYS_N / 8 + (1 << this.GFBITS) * 4 + this.SYS_T * 2 + 32];
        byte[] prev_sk = seed_b;
        long[] pivots = new long[]{0L};
        SHAKEDigest digest = new SHAKEDigest(256);

        int seedIndex;
        int[] perm;
        short[] pi;
        do {
            short[] field;
            int sigma1_t;
            int i;
            do {
                digest.update(seed_a, 0, seed_a.length);
                digest.update(seed_b, 0, seed_b.length);
                digest.doFinal(E, 0, E.length);
                seedIndex = E.length - 32;
                seed_b = Arrays.copyOfRange(E, seedIndex, seedIndex + 32);
                System.arraycopy(prev_sk, 0, sk, 0, 32);
                prev_sk = Arrays.copyOfRange(seed_b, 0, 32);
                field = new short[this.SYS_T];
                sigma1_t = E.length - 32 - 2 * this.SYS_T;

                for(i = 0; i < this.SYS_T; ++i) {
                    field[i] = Utils.load_gf(E, sigma1_t + i * 2, this.GFMASK);
                }
            } while(this.generate_irr_poly(field) == -1);

            int skIndex = 40;

            for(i = 0; i < this.SYS_T; ++i) {
                Utils.store_gf(sk, skIndex + i * 2, field[i]);
            }

            perm = new int[1 << this.GFBITS];
            seedIndex = sigma1_t - (1 << this.GFBITS) * 4;

            for(i = 0; i < 1 << this.GFBITS; ++i) {
                perm[i] = Utils.load4(E, seedIndex + i * 4);
            }

            pi = new short[1 << this.GFBITS];
        } while(this.pk_gen(pk, sk, perm, pi, pivots) == -1);

        byte[] out = new byte[this.COND_BYTES];
        controlbitsfrompermutation(out, pi, (long)this.GFBITS, (long)(1 << this.GFBITS));
        System.arraycopy(out, 0, sk, this.IRR_BYTES + 40, out.length);
        seedIndex -= this.SYS_N / 8;
        System.arraycopy(E, seedIndex, sk, sk.length - this.SYS_N / 8, this.SYS_N / 8);
        if (!this.usePivots) {
            Utils.store8(sk, 32, 4294967295L);
        } else {
            Utils.store8(sk, 32, pivots[0]);
        }

    }

    private void syndrome(byte[] cipher_text, byte[] pk, byte[] error_vector) {
        short[] row = new short[this.SYS_N / 8];
        int pk_ptr = 0;
        int tail = this.PK_NROWS % 8;

        int i;
        for(i = 0; i < this.SYND_BYTES; ++i) {
            cipher_text[i] = 0;
        }

        for(i = 0; i < this.PK_NROWS; ++i) {
            int j;
            for(j = 0; j < this.SYS_N / 8; ++j) {
                row[j] = 0;
            }

            for(j = 0; j < this.PK_ROW_BYTES; ++j) {
                row[this.SYS_N / 8 - this.PK_ROW_BYTES + j] = (short)pk[pk_ptr + j];
            }

            if (this.usePadding) {
                for(j = this.SYS_N / 8 - 1; j >= this.SYS_N / 8 - this.PK_ROW_BYTES; --j) {
                    row[j] = (short)(((row[j] & 255) << tail | (row[j - 1] & 255) >>> 8 - tail) & 255);
                }
            }

            row[i / 8] = (short)(row[i / 8] | 1 << i % 8);
            byte b = 0;

            for(j = 0; j < this.SYS_N / 8; ++j) {
                b = (byte)(b ^ row[j] & error_vector[j]);
            }

            b = (byte)(b ^ b >>> 4);
            b = (byte)(b ^ b >>> 2);
            b = (byte)(b ^ b >>> 1);
            b = (byte)(b & 1);
            cipher_text[i / 8] = (byte)(cipher_text[i / 8] | b << i % 8);
            pk_ptr += this.PK_ROW_BYTES;
        }

    }

    private void generate_error_vector(byte[] error_vector, SecureRandom random) {
        short[] buf_nums = new short[this.SYS_T * 2];
        short[] ind = new short[this.SYS_T];
        byte[] val = new byte[this.SYS_T];

        int i;
        int j;
        boolean eq;
        do {
            label84:
            do {
                byte[] buf_bytes;
                if (!this.countErrorIndices) {
                    buf_bytes = new byte[this.SYS_T * 2];
                    random.nextBytes(buf_bytes);
                    i = 0;

                    while(true) {
                        if (i >= this.SYS_T) {
                            break label84;
                        }

                        ind[i] = Utils.load_gf(buf_bytes, i * 2, this.GFMASK);
                        ++i;
                    }
                }

                buf_bytes = new byte[this.SYS_T * 4];
                random.nextBytes(buf_bytes);

                for(i = 0; i < this.SYS_T * 2; ++i) {
                    buf_nums[i] = Utils.load_gf(buf_bytes, i * 2, this.GFMASK);
                }

                i = 0;

                for(j = 0; j < this.SYS_T * 2 && i < this.SYS_T; ++j) {
                    if (buf_nums[j] < this.SYS_N) {
                        ind[i++] = buf_nums[j];
                    }
                }
            } while(i < this.SYS_T);

            eq = false;

            for(i = 1; i < this.SYS_T && !eq; ++i) {
                for(j = 0; j < i; ++j) {
                    if (ind[j] == ind[i]) {
                        eq = true;
                        break;
                    }
                }
            }
        } while(eq);

        for(i = 0; i < this.SYS_T; ++i) {
            val[i] = (byte)(1 << (ind[i] & 7));
        }

        for(i = 0; i < this.SYS_N / 8; ++i) {
            error_vector[i] = 0;

            for(j = 0; j < this.SYS_T; ++j) {
                short mask = (short)same_mask32((short) i, (short)(ind[j] >> 3));
                mask = (short)(mask & 255);
                error_vector[i] = (byte)(error_vector[i] | val[j] & mask);
            }
        }

    }

    private void encrypt(byte[] cipher_text, byte[] pk, byte[] error_vector, SecureRandom random) {
        this.generate_error_vector(error_vector, random);
        this.syndrome(cipher_text, pk, error_vector);
    }

    public int kem_enc(byte[] cipher_text, byte[] key, byte[] pk, SecureRandom random) {
        byte[] error_vector = new byte[this.SYS_N / 8];
        int padding_ok = 0;
        if (this.usePadding) {
            padding_ok = this.check_pk_padding(pk);
        }

        this.encrypt(cipher_text, pk, error_vector, random);
        Xof digest = new SHAKEDigest(256);
        digest.update((byte)2);
        digest.update(error_vector, 0, error_vector.length);
        digest.doFinal(cipher_text, this.SYND_BYTES, 32);
        digest.update((byte)1);
        digest.update(error_vector, 0, error_vector.length);
        digest.update(cipher_text, 0, cipher_text.length);
        digest.doFinal(key, 0, key.length);
        if (!this.usePadding) {
            return 0;
        } else {
            byte mask = (byte)padding_ok;
            mask = (byte)(mask ^ 255);

            int i;
            for(i = 0; i < this.SYND_BYTES + 32; ++i) {
                cipher_text[i] &= mask;
            }

            for(i = 0; i < 32; ++i) {
                key[i] &= mask;
            }

            return padding_ok;
        }
    }

    public int kem_dec(byte[] key, byte[] cipher_text, byte[] sk) {
        byte[] conf = new byte[32];
        byte[] error_vector = new byte[this.SYS_N / 8];
        int padding_ok = 0;
        if (this.usePadding) {
            padding_ok = this.check_c_padding(cipher_text);
        }

        byte ret_decrypt = (byte)this.decrypt(error_vector, sk, cipher_text);
        Xof digest = new SHAKEDigest(256);
        digest.update((byte)2);
        digest.update(error_vector, 0, error_vector.length);
        digest.doFinal(conf, 0, 32);
        byte ret_confirm = 0;

        int i;
        for(i = 0; i < 32; ++i) {
            ret_confirm = (byte)(ret_confirm | conf[i] ^ cipher_text[this.SYND_BYTES + i]);
        }

        short m = (short)(ret_decrypt | ret_confirm);
        --m;
        m = (short)(m >> 8);
        m = (short)(m & 255);
        byte[] preimage = new byte[1 + this.SYS_N / 8 + this.SYND_BYTES + 32];
        preimage[0] = (byte)(m & 1);

        for(i = 0; i < this.SYS_N / 8; ++i) {
            preimage[1 + i] = (byte)(~m & sk[i + 40 + this.IRR_BYTES + this.COND_BYTES] | m & error_vector[i]);
        }

        for(i = 0; i < this.SYND_BYTES + 32; ++i) {
            preimage[1 + this.SYS_N / 8 + i] = cipher_text[i];
        }

        digest = new SHAKEDigest(256);
        digest.update(preimage, 0, preimage.length);
        digest.doFinal(key, 0, key.length);
        if (!this.usePadding) {
            return 0;
        } else {
            byte mask = (byte)padding_ok;

            for(i = 0; i < key.length; ++i) {
                key[i] |= mask;
            }

            return padding_ok;
        }
    }

    private int decrypt(byte[] error_vector, byte[] sk, byte[] cipher_text) {
        short[] g = new short[this.SYS_T + 1];
        short[] L = new short[this.SYS_N];
        short[] s = new short[this.SYS_T * 2];
        short[] s_cmp = new short[this.SYS_T * 2];
        short[] locator = new short[this.SYS_T + 1];
        short[] images = new short[this.SYS_N];
        byte[] r = new byte[this.SYS_N / 8];

        int w;
        for(w = 0; w < this.SYND_BYTES; ++w) {
            r[w] = cipher_text[w];
        }

        for(w = this.SYND_BYTES; w < this.SYS_N / 8; ++w) {
            r[w] = 0;
        }

        for(w = 0; w < this.SYS_T; ++w) {
            g[w] = Utils.load_gf(sk, 40 + w * 2, this.GFMASK);
        }

        g[this.SYS_T] = 1;
        this.benes.support_gen(L, sk);
        this.synd(s, g, L, r);
        this.bm(locator, s);
        this.root(images, locator, L);

        for(w = 0; w < this.SYS_N / 8; ++w) {
            error_vector[w] = 0;
        }

        w = 0;

        int check;
        for(check = 0; check < this.SYS_N; ++check) {
            short t = (short)(this.gf.gf_iszero(images[check]) & 1);
            error_vector[check / 8] = (byte)(error_vector[check / 8] | t << check % 8);
            w += t;
        }

        this.synd(s_cmp, g, L, error_vector);
        check = w ^ this.SYS_T;

        for(int i = 0; i < this.SYS_T * 2; ++i) {
            check |= s[i] ^ s_cmp[i];
        }

        --check;
        check >>= 15;
        check &= 1;
        if ((check ^ 1) != 0) {
        }

        return check ^ 1;
    }

    private static int min(short a, int b) {
        return a < b ? a : b;
    }

    private void bm(short[] out, short[] s) {
        short L = 0;
        short[] T = new short[this.SYS_T + 1];
        short[] C = new short[this.SYS_T + 1];
        short[] B = new short[this.SYS_T + 1];
        short b = 1;

        int i;
        for(i = 0; i < this.SYS_T + 1; ++i) {
            C[i] = B[i] = 0;
        }

        B[1] = C[0] = 1;

        for(short N = 0; N < 2 * this.SYS_T; ++N) {
            short d = 0;

            for(i = 0; i <= min(N, this.SYS_T); ++i) {
                d ^= this.gf.gf_mul(C[i], s[N - i]);
            }

            short mne = (short)(d - 1);
            mne = (short)(mne >> 15);
            mne = (short)(mne & 1);
            --mne;
            short mle = (short)(N - 2 * L);
            mle = (short)(mle >> 15);
            mle = (short)(mle & 1);
            --mle;
            mle &= mne;

            for(i = 0; i <= this.SYS_T; ++i) {
                T[i] = C[i];
            }

            short f = this.gf.gf_frac(b, d);

            for(i = 0; i <= this.SYS_T; ++i) {
                C[i] = (short)(C[i] ^ this.gf.gf_mul(f, B[i]) & mne);
            }

            L = (short)(L & ~mle | N + 1 - L & mle);

            for(i = 0; i <= this.SYS_T; ++i) {
                B[i] = (short)(B[i] & ~mle | T[i] & mle);
            }

            b = (short)(b & ~mle | d & mle);

            for(i = this.SYS_T; i >= 1; --i) {
                B[i] = B[i - 1];
            }

            B[0] = 0;
        }

        for(i = 0; i <= this.SYS_T; ++i) {
            out[i] = C[this.SYS_T - i];
        }

    }

    private void synd(short[] out, short[] f, short[] L, byte[] r) {
        int j;
        for(j = 0; j < 2 * this.SYS_T; ++j) {
            out[j] = 0;
        }

        for(int i = 0; i < this.SYS_N; ++i) {
            short c = (short)(r[i / 8] >> i % 8 & 1);
            short e = this.eval(f, L[i]);
            short e_inv = this.gf.gf_inv(this.gf.gf_mul(e, e));

            for(j = 0; j < 2 * this.SYS_T; ++j) {
                out[j] = this.gf.gf_add(out[j], this.gf.gf_mul(e_inv, c));
                e_inv = this.gf.gf_mul(e_inv, L[i]);
            }
        }

    }

    private int mov_columns(byte[][] mat, short[] pi, long[] pivots) {
        long[] buf = new long[64];
        long[] ctz_list = new long[32];
        long one = 1L;
        byte[] tmp = new byte[9];
        int row = this.PK_NROWS - 32;
        int block_idx = row / 8;
        int tail = row % 8;
        int i;
        int j;
        if (this.usePadding) {
            for(i = 0; i < 32; ++i) {
                for(j = 0; j < 9; ++j) {
                    tmp[j] = mat[row + i][block_idx + j];
                }

                for(j = 0; j < 8; ++j) {
                    tmp[j] = (byte)((tmp[j] & 255) >> tail | tmp[j + 1] << 8 - tail);
                }

                buf[i] = Utils.load8(tmp, 0);
            }
        } else {
            for(i = 0; i < 32; ++i) {
                buf[i] = Utils.load8(mat[row + i], block_idx);
            }
        }

        pivots[0] = 0L;

        long t;
        for(i = 0; i < 32; ++i) {
            t = buf[i];

            for(j = i + 1; j < 32; ++j) {
                t |= buf[j];
            }

            if (t == 0L) {
                return -1;
            }

            int s;
            ctz_list[i] = (long)(s = ctz(t));
            pivots[0] |= one << (int)ctz_list[i];

            long mask;
            for(j = i + 1; j < 32; ++j) {
                mask = buf[i] >> s & 1L;
                --mask;
                buf[i] ^= buf[j] & mask;
            }

            for(j = i + 1; j < 32; ++j) {
                mask = buf[j] >> s & 1L;
                mask = -mask;
                buf[j] ^= buf[i] & mask;
            }
        }

        int k;
        long d;
        for(j = 0; j < 32; ++j) {
            for(k = j + 1; k < 64; ++k) {
                d = (long)(pi[row + j] ^ pi[row + k]);
                d &= same_mask64((short)k, (short)((int)ctz_list[j]));
                pi[row + j] = (short)((int)((long)pi[row + j] ^ d));
                pi[row + k] = (short)((int)((long)pi[row + k] ^ d));
            }
        }

        for(i = 0; i < this.PK_NROWS; ++i) {
            if (!this.usePadding) {
                t = Utils.load8(mat[i], block_idx);
            } else {
                for(k = 0; k < 9; ++k) {
                    tmp[k] = mat[i][block_idx + k];
                }

                for(k = 0; k < 8; ++k) {
                    tmp[k] = (byte)((tmp[k] & 255) >> tail | tmp[k + 1] << 8 - tail);
                }

                t = Utils.load8(tmp, 0);
            }

            for(j = 0; j < 32; ++j) {
                d = t >> j;
                d ^= t >> (int)ctz_list[j];
                d &= 1L;
                t ^= d << (int)ctz_list[j];
                t ^= d << j;
            }

            if (this.usePadding) {
                Utils.store8(tmp, 0, t);
                mat[i][block_idx + 8] = (byte)((mat[i][block_idx + 8] & 255) >>> tail << tail | (tmp[7] & 255) >>> 8 - tail);
                mat[i][block_idx + 0] = (byte)((tmp[0] & 255) << tail | (mat[i][block_idx] & 255) << 8 - tail >>> 8 - tail);

                for(k = 7; k >= 1; --k) {
                    mat[i][block_idx + k] = (byte)((tmp[k] & 255) << tail | (tmp[k - 1] & 255) >>> 8 - tail);
                }
            } else {
                Utils.store8(mat[i], block_idx, t);
            }
        }

        return 0;
    }

    private static int ctz(long in) {
        int m = 0;
        int r = 0;

        for(int i = 0; i < 64; ++i) {
            int b = (int)(in >> i & 1L);
            m |= b;
            r += (m ^ 1) & (b ^ 1);
        }

        return r;
    }

    private static long same_mask64(short x, short y) {
        long mask = (long)(x ^ y);
        --mask;
        mask >>>= 63;
        mask = -mask;
        return mask;
    }

    private static byte same_mask32(short x, short y) {
        int mask = x ^ y;
        --mask;
        mask >>>= 31;
        mask = -mask;
        return (byte)(mask & 255);
    }

    private static void layer(short[] p, byte[] out, int ptrIndex, int s, int n) {
        int stride = 1 << s;
        int index = 0;

        for(int i = 0; i < n; i += stride * 2) {
            for(int j = 0; j < stride; ++j) {
                int d = p[i + j] ^ p[i + j + stride];
                int m = out[ptrIndex + (index >> 3)] >> (index & 7) & 1;
                m = -m;
                d &= m;
                p[i + j] = (short)(p[i + j] ^ d);
                p[i + j + stride] = (short)(p[i + j + stride] ^ d);
                ++index;
            }
        }

    }

    private static void controlbitsfrompermutation(byte[] out, short[] pi, long w, long n) {
        int[] temp = new int[(int)(2L * n)];
        short[] pi_test = new short[(int)n];

        short diff;
        do {
            int i;
            for(i = 0; (long)i < ((2L * w - 1L) * n / 2L + 7L) / 8L; ++i) {
                out[i] = 0;
            }

            cbrecursion(out, 0L, 1L, pi, 0, w, n, temp);

            for(i = 0; (long)i < n; ++i) {
                pi_test[i] = (short)i;
            }

            int ptrIndex = 0;

            for(i = 0; (long)i < w; ++i) {
                layer(pi_test, out, ptrIndex, i, (int)n);
                ptrIndex = (int)((long)ptrIndex + (n >> 4));
            }

            for(i = (int)(w - 2L); i >= 0; --i) {
                layer(pi_test, out, ptrIndex, i, (int)n);
                ptrIndex = (int)((long)ptrIndex + (n >> 4));
            }

            diff = 0;

            for(i = 0; (long)i < n; ++i) {
                diff = (short)(diff | pi[i] ^ pi_test[i]);
            }
        } while(diff != 0);

    }

    static short get_q_short(int[] temp, int q_index) {
        int temp_index = q_index / 2;
        return q_index % 2 == 0 ? (short)temp[temp_index] : (short)((temp[temp_index] & -65536) >> 16);
    }

    static void cbrecursion(byte[] out, long pos, long step, short[] pi, int qIndex, long w, long n, int[] temp) {
        if (w == 1L) {
            out[(int)(pos >> 3)] = (byte)(out[(int)(pos >> 3)] ^ get_q_short(temp, qIndex) << (int)(pos & 7L));
        } else {
            long x;
            if (pi != null) {
                for(x = 0L; x < n; ++x) {
                    temp[(int)x] = (pi[(int)x] ^ 1) << 16 | pi[(int)(x ^ 1L)];
                }
            } else {
                for(x = 0L; x < n; ++x) {
                    temp[(int)x] = (get_q_short(temp, (int)((long)qIndex + x)) ^ 1) << 16 | get_q_short(temp, (int)((long)qIndex + (x ^ 1L)));
                }
            }

            sort32(temp, 0, (int)n);

            int cpx;
            int ppcx;
            int lk;
            for(x = 0L; x < n; ++x) {
                cpx = temp[(int)x];
                ppcx = cpx & '\uffff';
                lk = ppcx;
                if (x < (long)ppcx) {
                    lk = (int)x;
                }

                temp[(int)(n + x)] = ppcx << 16 | lk;
            }

            for(x = 0L; x < n; ++x) {
                temp[(int)x] = (int)((long)(temp[(int)x] << 16) | x);
            }

            sort32(temp, 0, (int)n);

            for(x = 0L; x < n; ++x) {
                temp[(int)x] = (temp[(int)x] << 16) + (temp[(int)(n + x)] >> 16);
            }

            sort32(temp, 0, (int)n);
            long i;
            if (w <= 10L) {
                for(x = 0L; x < n; ++x) {
                    temp[(int)(n + x)] = (temp[(int)x] & '\uffff') << 10 | temp[(int)(n + x)] & 1023;
                }

                for(i = 1L; i < w - 1L; ++i) {
                    for(x = 0L; x < n; ++x) {
                        temp[(int)x] = (int)((long)((temp[(int)(n + x)] & -1024) << 6) | x);
                    }

                    sort32(temp, 0, (int)n);

                    for(x = 0L; x < n; ++x) {
                        temp[(int)x] = temp[(int)x] << 20 | temp[(int)(n + x)];
                    }

                    sort32(temp, 0, (int)n);

                    for(x = 0L; x < n; ++x) {
                        cpx = temp[(int)x] & 1048575;
                        ppcx = temp[(int)x] & 1047552 | temp[(int)(n + x)] & 1023;
                        if (cpx < ppcx) {
                            ppcx = cpx;
                        }

                        temp[(int)(n + x)] = ppcx;
                    }
                }

                for(x = 0L; x < n; ++x) {
                    temp[(int)(n + x)] &= 1023;
                }
            } else {
                for(x = 0L; x < n; ++x) {
                    temp[(int)(n + x)] = temp[(int)x] << 16 | temp[(int)(n + x)] & '\uffff';
                }

                for(i = 1L; i < w - 1L; ++i) {
                    for(x = 0L; x < n; ++x) {
                        temp[(int)x] = (int)((long)(temp[(int)(n + x)] & -65536) | x);
                    }

                    sort32(temp, 0, (int)n);

                    for(x = 0L; x < n; ++x) {
                        temp[(int)x] = temp[(int)x] << 16 | temp[(int)(n + x)] & '\uffff';
                    }

                    if (i < w - 2L) {
                        for(x = 0L; x < n; ++x) {
                            temp[(int)(n + x)] = temp[(int)x] & -65536 | temp[(int)(n + x)] >> 16;
                        }

                        sort32(temp, (int)n, (int)(n * 2L));

                        for(x = 0L; x < n; ++x) {
                            temp[(int)(n + x)] = temp[(int)(n + x)] << 16 | temp[(int)x] & '\uffff';
                        }
                    }

                    sort32(temp, 0, (int)n);

                    for(x = 0L; x < n; ++x) {
                        cpx = temp[(int)(n + x)] & -65536 | temp[(int)x] & '\uffff';
                        if (cpx < temp[(int)(n + x)]) {
                            temp[(int)(n + x)] = cpx;
                        }
                    }
                }

                for(x = 0L; x < n; ++x) {
                    temp[(int)(n + x)] &= 65535;
                }
            }

            if (pi != null) {
                for(x = 0L; x < n; ++x) {
                    temp[(int)x] = (int)((long)(pi[(int)x] << 16) + x);
                }
            } else {
                for(x = 0L; x < n; ++x) {
                    temp[(int)x] = (int)((long)(get_q_short(temp, (int)((long)qIndex + x)) << 16) + x);
                }
            }

            sort32(temp, 0, (int)n);

            long j;
            int Ly;
            int Ly1;
            long y;
            for(j = 0L; j < n / 2L; ++j) {
                y = 2L * j;
                lk = temp[(int)(n + y)] & 1;
                Ly = (int)(y + (long)lk);
                Ly1 = Ly ^ 1;
                out[(int)(pos >> 3)] = (byte)(out[(int)(pos >> 3)] ^ lk << (int)(pos & 7L));
                pos += step;
                temp[(int)(n + y)] = temp[(int)y] << 16 | Ly;
                temp[(int)(n + y + 1L)] = temp[(int)(y + 1L)] << 16 | Ly1;
            }

            sort32(temp, (int)n, (int)(n * 2L));
            pos += (2L * w - 3L) * step * (n / 2L);

            for(long k = 0L; k < n / 2L; ++k) {
                y = 2L * k;
                lk = temp[(int)(n + y)] & 1;
                Ly = (int)(y + (long)lk);
                Ly1 = Ly ^ 1;
                out[(int)(pos >> 3)] = (byte)(out[(int)(pos >> 3)] ^ lk << (int)(pos & 7L));
                pos += step;
                temp[(int)y] = Ly << 16 | temp[(int)(n + y)] & '\uffff';
                temp[(int)(y + 1L)] = Ly1 << 16 | temp[(int)(n + y + 1L)] & '\uffff';
            }

            sort32(temp, 0, (int)n);
            pos -= (2L * w - 2L) * step * (n / 2L);
            short[] q = new short[(int)n * 4];

            for(i = 0L; i < n * 2L; ++i) {
                q[(int)(i * 2L + 0L)] = (short)temp[(int)i];
                q[(int)(i * 2L + 1L)] = (short)((temp[(int)i] & -65536) >> 16);
            }

            for(j = 0L; j < n / 2L; ++j) {
                q[(int)j] = (short)((temp[(int)(2L * j)] & '\uffff') >>> 1);
                q[(int)(j + n / 2L)] = (short)((temp[(int)(2L * j + 1L)] & '\uffff') >>> 1);
            }

            for(i = 0L; i < n / 2L; ++i) {
                temp[(int)(n + n / 4L + i)] = q[(int)(i * 2L + 1L)] << 16 | q[(int)(i * 2L)];
            }

            cbrecursion(out, pos, step * 2L, (short[])null, (int)(n + n / 4L) * 2, w - 1L, n / 2L, temp);
            cbrecursion(out, pos + step, step * 2L, (short[])null, (int)((n + n / 4L) * 2L + n / 2L), w - 1L, n / 2L, temp);
        }
    }

    private int pk_gen(byte[] pk, byte[] sk, int[] perm, short[] pi, long[] pivots) {
        short[] g = new short[this.SYS_T + 1];
        g[this.SYS_T] = 1;

        int i;
        for(i = 0; i < this.SYS_T; ++i) {
            g[i] = Utils.load_gf(sk, 40 + i * 2, this.GFMASK);
        }

        long[] buf = new long[1 << this.GFBITS];

        for(i = 0; i < 1 << this.GFBITS; ++i) {
            buf[i] = (long)perm[i];
            buf[i] <<= 31;
            buf[i] |= (long)i;
            buf[i] &= 9223372036854775807L;
        }

        sort64(buf, 0, buf.length);

        for(i = 1; i < 1 << this.GFBITS; ++i) {
            if (buf[i - 1] >> 31 == buf[i] >> 31) {
                return -1;
            }
        }

        short[] L = new short[this.SYS_N];

        for(i = 0; i < 1 << this.GFBITS; ++i) {
            pi[i] = (short)((int)(buf[i] & (long)this.GFMASK));
        }

        for(i = 0; i < this.SYS_N; ++i) {
            L[i] = Utils.bitrev(pi[i], this.GFBITS);
        }

        short[] inv = new short[this.SYS_N];
        this.root(inv, g, L);

        for(i = 0; i < this.SYS_N; ++i) {
            inv[i] = this.gf.gf_inv(inv[i]);
        }

        byte[][] mat = new byte[this.PK_NROWS][this.SYS_N / 8];

        int j;
        for(i = 0; i < this.PK_NROWS; ++i) {
            for(j = 0; j < this.SYS_N / 8; ++j) {
                mat[i][j] = 0;
            }
        }

        int k;
        for(i = 0; i < this.SYS_T; ++i) {
            for(j = 0; j < this.SYS_N; j += 8) {
                for(k = 0; k < this.GFBITS; ++k) {
                    byte b = (byte)(inv[j + 7] >>> k & 1);
                    b = (byte)(b << 1);
                    b = (byte)(b | inv[j + 6] >>> k & 1);
                    b = (byte)(b << 1);
                    b = (byte)(b | inv[j + 5] >>> k & 1);
                    b = (byte)(b << 1);
                    b = (byte)(b | inv[j + 4] >>> k & 1);
                    b = (byte)(b << 1);
                    b = (byte)(b | inv[j + 3] >>> k & 1);
                    b = (byte)(b << 1);
                    b = (byte)(b | inv[j + 2] >>> k & 1);
                    b = (byte)(b << 1);
                    b = (byte)(b | inv[j + 1] >>> k & 1);
                    b = (byte)(b << 1);
                    b = (byte)(b | inv[j + 0] >>> k & 1);
                    mat[i * this.GFBITS + k][j / 8] = b;
                }
            }

            for(j = 0; j < this.SYS_N; ++j) {
                inv[j] = this.gf.gf_mul(inv[j], L[j]);
            }
        }

        for(i = 0; i < (this.PK_NROWS + 7) / 8; ++i) {
            for(j = 0; j < 8; ++j) {
                int row = i * 8 + j;
                if (row >= this.PK_NROWS) {
                    break;
                }

                if (this.usePivots && row == this.PK_NROWS - 32 && this.mov_columns(mat, pi, pivots) != 0) {
                    return -1;
                }

                int c;
                byte mask;
                for(k = row + 1; k < this.PK_NROWS; ++k) {
                    mask = (byte)(mat[row][i] ^ mat[k][i]);
                    mask = (byte)(mask >> j);
                    mask = (byte)(mask & 1);
                    mask = (byte)(-mask);

                    for(c = 0; c < this.SYS_N / 8; ++c) {
                        mat[row][c] = (byte)(mat[row][c] ^ mat[k][c] & mask);
                    }
                }

                if ((mat[row][i] >> j & 1) == 0) {
                    return -1;
                }

                for(k = 0; k < this.PK_NROWS; ++k) {
                    if (k != row) {
                        mask = (byte)(mat[k][i] >> j);
                        mask = (byte)(mask & 1);
                        mask = (byte)(-mask);

                        for(c = 0; c < this.SYS_N / 8; ++c) {
                            mat[k][c] = (byte)(mat[k][c] ^ mat[row][c] & mask);
                        }
                    }
                }
            }
        }

        if (pk != null) {
            if (this.usePadding) {
                int pk_index = 0;
                int tail = this.PK_NROWS % 8;

                for(i = 0; i < this.PK_NROWS; ++i) {
                    for(j = (this.PK_NROWS - 1) / 8; j < this.SYS_N / 8 - 1; ++j) {
                        pk[pk_index++] = (byte)((mat[i][j] & 255) >>> tail | mat[i][j + 1] << 8 - tail);
                    }

                    pk[pk_index++] = (byte)((mat[i][j] & 255) >>> tail);
                }
            } else {
                for(i = 0; i < this.PK_NROWS; ++i) {
                    k = 0;

                    for(j = 0; j < (this.SYS_N - this.PK_NROWS + 7) / 8; ++j) {
                        pk[i * ((this.SYS_N - this.PK_NROWS + 7) / 8) + k] = mat[i][j + this.PK_NROWS / 8];
                        ++k;
                    }
                }
            }
        }

        return 0;
    }

    private short eval(short[] f, short a) {
        short r = f[this.SYS_T];

        for(int i = this.SYS_T - 1; i >= 0; --i) {
            r = this.gf.gf_mul(r, a);
            r = this.gf.gf_add(r, f[i]);
        }

        return r;
    }

    private void root(short[] out, short[] f, short[] L) {
        for(int i = 0; i < this.SYS_N; ++i) {
            out[i] = this.eval(f, L[i]);
        }

    }

    private int generate_irr_poly(short[] field) {
        short[][] m = new short[this.SYS_T + 1][this.SYS_T];
        m[0][0] = 1;

        int j;
        for(j = 1; j < this.SYS_T; ++j) {
            m[0][j] = 0;
        }

        for(j = 0; j < this.SYS_T; ++j) {
            m[1][j] = field[j];
        }

        for(j = 2; j <= this.SYS_T; ++j) {
            this.GF_mul(m[j], m[j - 1], field);
        }

        for(j = 0; j < this.SYS_T; ++j) {
            for(int k = j + 1; k < this.SYS_T; ++k) {
                short mask = this.gf.gf_iszero(m[j][j]);

                for(int c = j; c < this.SYS_T + 1; ++c) {
                    short temp = (short)(m[c][j] ^ m[c][k] & mask);
                    m[c][j] = temp;
                }
            }

            if (m[j][j] == 0) {
                return -1;
            }

            short inv = this.gf.gf_inv(m[j][j]);

            int k;
            for(k = j; k < this.SYS_T + 1; ++k) {
                m[k][j] = this.gf.gf_mul(m[k][j], inv);
            }

            for(k = 0; k < this.SYS_T; ++k) {
                if (k != j) {
                    short t = m[j][k];

                    for(int c = j; c < this.SYS_T + 1; ++c) {
                        m[c][k] ^= this.gf.gf_mul(m[c][j], t);
                    }
                }
            }
        }

        for(j = 0; j < this.SYS_T; ++j) {
            field[j] = m[this.SYS_T][j];
        }

        return 0;
    }

    private void GF_mul(short[] out, short[] left, short[] right) {
        short[] prod = new short[this.SYS_T * 2 - 1];

        int i;
        for(i = 0; i < this.SYS_T * 2 - 1; ++i) {
            prod[i] = 0;
        }

        int j;
        for(i = 0; i < this.SYS_T; ++i) {
            for(j = 0; j < this.SYS_T; ++j) {
                short temp = this.gf.gf_mul(left[i], right[j]);
                prod[i + j] ^= temp;
            }
        }

        for(i = (this.SYS_T - 1) * 2; i >= this.SYS_T; --i) {
            for(j = 0; j != this.poly.length; ++j) {
                int polyIndex = this.poly[j];
                int var10001;
                if (polyIndex == 0 && this.GFBITS == 12) {
                    var10001 = i - this.SYS_T;
                    prod[var10001] ^= this.gf.gf_mul(prod[i], (short)2);
                } else {
                    var10001 = i - this.SYS_T + polyIndex;
                    prod[var10001] ^= prod[i];
                }
            }
        }

        System.arraycopy(prod, 0, out, 0, this.SYS_T);

        for(i = 0; i < this.SYS_T; ++i) {
            out[i] = prod[i];
        }

    }

    int check_pk_padding(byte[] pk) {
        byte b = 0;

        for(int i = 0; i < this.PK_NROWS; ++i) {
            b |= pk[i * this.PK_ROW_BYTES + this.PK_ROW_BYTES - 1];
        }

        b = (byte)((b & 255) >>> this.PK_NCOLS % 8);
        --b;
        b = (byte)((b & 255) >>> 7);
        return b - 1;
    }

    int check_c_padding(byte[] c) {
        byte b = (byte)((c[this.SYND_BYTES - 1] & 255) >>> this.PK_NROWS % 8);
        --b;
        b = (byte)((b & 255) >>> 7);
        return b - 1;
    }

    public int getDefaultSessionKeySize() {
        return this.defaultKeySize;
    }

    private static void sort32(int[] temp, int from, int to) {
        int n = to - from;
        if (n >= 2) {
            int top;
            for(top = 1; top < n - top; top += top) {
            }

            for(int p = top; p > 0; p >>>= 1) {
                int i;
                int a;
                int ab;
                for(i = 0; i < n - p; ++i) {
                    if ((i & p) == 0) {
                        a = temp[from + i + p] ^ temp[from + i];
                        ab = temp[from + i + p] - temp[from + i];
                        ab ^= a & (ab ^ temp[from + i + p]);
                        ab >>= 31;
                        ab &= a;
                        temp[from + i] ^= ab;
                        temp[from + i + p] ^= ab;
                    }
                }

                i = 0;

                for(int q = top; q > p; q >>>= 1) {
                    for(; i < n - q; ++i) {
                        if ((i & p) == 0) {
                            a = temp[from + i + p];

                            for(int r = q; r > p; r >>>= 1) {
                                ab = temp[from + i + r] ^ a;
                                int c = temp[from + i + r] - a;
                                c ^= ab & (c ^ temp[from + i + r]);
                                c >>= 31;
                                c &= ab;
                                a ^= c;
                                temp[from + i + r] ^= c;
                            }

                            temp[from + i + p] = a;
                        }
                    }
                }
            }

        }
    }

    private static void sort64(long[] temp, int from, int to) {
        int n = to - from;
        if (n >= 2) {
            int top;
            for(top = 1; top < n - top; top += top) {
            }

            for(int p = top; p > 0; p >>>= 1) {
                int i;
                long a;
                for(i = 0; i < n - p; ++i) {
                    if ((i & p) == 0) {
                        a = temp[from + i + p] - temp[from + i];
                        a >>>= 63;
                        a = -a;
                        a &= temp[from + i] ^ temp[from + i + p];
                        temp[from + i] ^= a;
                        temp[from + i + p] ^= a;
                    }
                }

                i = 0;

                for(int q = top; q > p; q >>>= 1) {
                    for(; i < n - q; ++i) {
                        if ((i & p) == 0) {
                            a = temp[from + i + p];

                            for(int r = q; r > p; r >>>= 1) {
                                long c = temp[from + i + r] - a;
                                c >>>= 63;
                                c = -c;
                                c &= a ^ temp[from + i + r];
                                a ^= c;
                                temp[from + i + r] ^= c;
                            }

                            temp[from + i + p] = a;
                        }
                    }
                }
            }

        }
    }
}