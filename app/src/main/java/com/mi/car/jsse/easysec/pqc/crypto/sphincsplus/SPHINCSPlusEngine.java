package com.mi.car.jsse.easysec.pqc.crypto.sphincsplus;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.crypto.generators.MGF1BytesGenerator;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.MGFParameters;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

abstract class SPHINCSPlusEngine {
    final int A;
    final int D;
    final int H;
    final int H_PRIME;
    final int K;
    final int N;
    final int T;
    final int WOTS_LEN;
    final int WOTS_LEN1;
    final int WOTS_LEN2;
    final int WOTS_LOGW;
    final int WOTS_W;
    final boolean robust;

    /* access modifiers changed from: package-private */
    public abstract byte[] F(byte[] bArr, ADRS adrs, byte[] bArr2);

    /* access modifiers changed from: package-private */
    public abstract byte[] H(byte[] bArr, ADRS adrs, byte[] bArr2, byte[] bArr3);

    /* access modifiers changed from: package-private */
    public abstract IndexedDigest H_msg(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4);

    /* access modifiers changed from: package-private */
    public abstract byte[] PRF(byte[] bArr, byte[] bArr2, ADRS adrs);

    /* access modifiers changed from: package-private */
    public abstract byte[] PRF_msg(byte[] bArr, byte[] bArr2, byte[] bArr3);

    /* access modifiers changed from: package-private */
    public abstract byte[] T_l(byte[] bArr, ADRS adrs, byte[] bArr2);

    protected static byte[] xor(byte[] m, byte[] mask) {
        byte[] r = Arrays.clone(m);
        for (int t = 0; t < m.length; t++) {
            r[t] = (byte) (r[t] ^ mask[t]);
        }
        return r;
    }

    public SPHINCSPlusEngine(boolean robust2, int n, int w, int d, int a, int k, int h) {
        this.N = n;
        if (w == 16) {
            this.WOTS_LOGW = 4;
            this.WOTS_LEN1 = (this.N * 8) / this.WOTS_LOGW;
            if (this.N <= 8) {
                this.WOTS_LEN2 = 2;
            } else if (this.N <= 136) {
                this.WOTS_LEN2 = 3;
            } else if (this.N <= 256) {
                this.WOTS_LEN2 = 4;
            } else {
                throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
            }
        } else if (w == 256) {
            this.WOTS_LOGW = 8;
            this.WOTS_LEN1 = (this.N * 8) / this.WOTS_LOGW;
            if (this.N <= 1) {
                this.WOTS_LEN2 = 1;
            } else if (this.N <= 256) {
                this.WOTS_LEN2 = 2;
            } else {
                throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
            }
        } else {
            throw new IllegalArgumentException("wots_w assumed 16 or 256");
        }
        this.WOTS_W = w;
        this.WOTS_LEN = this.WOTS_LEN1 + this.WOTS_LEN2;
        this.robust = robust2;
        this.D = d;
        this.A = a;
        this.K = k;
        this.H = h;
        this.H_PRIME = h / d;
        this.T = 1 << a;
    }

    static class Sha256Engine extends SPHINCSPlusEngine {
        private final byte[] digestBuf;
        private final byte[] hmacBuf;
        private final MGF1BytesGenerator mgf1;
        private final Digest msgDigest;
        private final byte[] padding = new byte[64];
        private final Digest treeDigest = new SHA256Digest();
        private final HMac treeHMac;

        public Sha256Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
            super(robust, n, w, d, a, k, h);
            if (n == 32) {
                this.msgDigest = new SHA512Digest();
                this.treeHMac = new HMac(new SHA512Digest());
                this.mgf1 = new MGF1BytesGenerator(new SHA512Digest());
            } else {
                this.msgDigest = new SHA256Digest();
                this.treeHMac = new HMac(new SHA256Digest());
                this.mgf1 = new MGF1BytesGenerator(new SHA256Digest());
            }
            this.digestBuf = new byte[this.treeDigest.getDigestSize()];
            this.hmacBuf = new byte[this.treeHMac.getMacSize()];
        }

        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1) {
            byte[] compressedADRS = compressedADRS(adrs);
            if (this.robust) {
                m1 = bitmask256(Arrays.concatenate(pkSeed, compressedADRS), m1);
            }
            this.treeDigest.update(pkSeed, 0, pkSeed.length);
            this.treeDigest.update(this.padding, 0, 64 - pkSeed.length);
            this.treeDigest.update(compressedADRS, 0, compressedADRS.length);
            this.treeDigest.update(m1, 0, m1.length);
            this.treeDigest.doFinal(this.digestBuf, 0);
            return Arrays.copyOfRange(this.digestBuf, 0, this.N);
        }

        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
            byte[] m1m2 = Arrays.concatenate(m1, m2);
            byte[] compressedADRS = compressedADRS(adrs);
            if (this.robust) {
                m1m2 = bitmask256(Arrays.concatenate(pkSeed, compressedADRS), m1m2);
            }
            this.treeDigest.update(pkSeed, 0, pkSeed.length);
            this.treeDigest.update(this.padding, 0, 64 - this.N);
            this.treeDigest.update(compressedADRS, 0, compressedADRS.length);
            this.treeDigest.update(m1m2, 0, m1m2.length);
            this.treeDigest.doFinal(this.digestBuf, 0);
            return Arrays.copyOfRange(this.digestBuf, 0, this.N);
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message) {
            int forsMsgBytes = ((this.A * this.K) + 7) / 8;
            int leafBits = this.H / this.D;
            int treeBits = this.H - leafBits;
            int leafBytes = (leafBits + 7) / 8;
            int treeBytes = (treeBits + 7) / 8;
            byte[] dig = new byte[this.msgDigest.getDigestSize()];
            this.msgDigest.update(prf, 0, prf.length);
            this.msgDigest.update(pkSeed, 0, pkSeed.length);
            this.msgDigest.update(pkRoot, 0, pkRoot.length);
            this.msgDigest.update(message, 0, message.length);
            this.msgDigest.doFinal(dig, 0);
            byte[] out = bitmask(Arrays.concatenate(prf, pkSeed, dig), new byte[(forsMsgBytes + leafBytes + treeBytes)]);
            byte[] treeIndexBuf = new byte[8];
            System.arraycopy(out, forsMsgBytes, treeIndexBuf, 8 - treeBytes, treeBytes);
            long treeIndex = Pack.bigEndianToLong(treeIndexBuf, 0) & (-1 >>> (64 - treeBits));
            byte[] leafIndexBuf = new byte[4];
            System.arraycopy(out, forsMsgBytes + treeBytes, leafIndexBuf, 4 - leafBytes, leafBytes);
            return new IndexedDigest(treeIndex, Pack.bigEndianToInt(leafIndexBuf, 0) & (-1 >>> (32 - leafBits)), Arrays.copyOfRange(out, 0, forsMsgBytes));
        }

        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m) {
            byte[] compressedADRS = compressedADRS(adrs);
            if (this.robust) {
                m = bitmask256(Arrays.concatenate(pkSeed, compressedADRS), m);
            }
            this.treeDigest.update(pkSeed, 0, pkSeed.length);
            this.treeDigest.update(this.padding, 0, 64 - this.N);
            this.treeDigest.update(compressedADRS, 0, compressedADRS.length);
            this.treeDigest.update(m, 0, m.length);
            this.treeDigest.doFinal(this.digestBuf, 0);
            return Arrays.copyOfRange(this.digestBuf, 0, this.N);
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs) {
            int n = skSeed.length;
            this.treeDigest.update(skSeed, 0, skSeed.length);
            byte[] compressedADRS = compressedADRS(adrs);
            this.treeDigest.update(compressedADRS, 0, compressedADRS.length);
            this.treeDigest.doFinal(this.digestBuf, 0);
            return Arrays.copyOfRange(this.digestBuf, 0, n);
        }

        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message) {
            this.treeHMac.init(new KeyParameter(prf));
            this.treeHMac.update(randomiser, 0, randomiser.length);
            this.treeHMac.update(message, 0, message.length);
            this.treeHMac.doFinal(this.hmacBuf, 0);
            return Arrays.copyOfRange(this.hmacBuf, 0, this.N);
        }

        private byte[] compressedADRS(ADRS adrs) {
            byte[] rv = new byte[22];
            System.arraycopy(adrs.value, 3, rv, 0, 1);
            System.arraycopy(adrs.value, 8, rv, 1, 8);
            System.arraycopy(adrs.value, 19, rv, 9, 1);
            System.arraycopy(adrs.value, 20, rv, 10, 12);
            return rv;
        }

        /* access modifiers changed from: protected */
        public byte[] bitmask(byte[] key, byte[] m) {
            byte[] mask = new byte[m.length];
            this.mgf1.init(new MGFParameters(key));
            this.mgf1.generateBytes(mask, 0, mask.length);
            for (int i = 0; i < m.length; i++) {
                mask[i] = (byte) (mask[i] ^ m[i]);
            }
            return mask;
        }

        /* access modifiers changed from: protected */
        public byte[] bitmask256(byte[] key, byte[] m) {
            byte[] mask = new byte[m.length];
            MGF1BytesGenerator mgf12 = new MGF1BytesGenerator(new SHA256Digest());
            mgf12.init(new MGFParameters(key));
            mgf12.generateBytes(mask, 0, mask.length);
            for (int i = 0; i < m.length; i++) {
                mask[i] = (byte) (mask[i] ^ m[i]);
            }
            return mask;
        }
    }

    static class Shake256Engine extends SPHINCSPlusEngine {
        private final Xof treeDigest = new SHAKEDigest(256);

        public Shake256Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
            super(robust, n, w, d, a, k, h);
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1) {
            byte[] mTheta = m1;
            if (this.robust) {
                mTheta = bitmask(pkSeed, adrs, m1);
            }
            byte[] rv = new byte[this.N];
            this.treeDigest.update(pkSeed, 0, pkSeed.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.update(mTheta, 0, mTheta.length);
            this.treeDigest.doFinal(rv, 0, rv.length);
            return rv;
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
            byte[] m1m2 = Arrays.concatenate(m1, m2);
            if (this.robust) {
                m1m2 = bitmask(pkSeed, adrs, m1m2);
            }
            byte[] rv = new byte[this.N];
            this.treeDigest.update(pkSeed, 0, pkSeed.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.update(m1m2, 0, m1m2.length);
            this.treeDigest.doFinal(rv, 0, rv.length);
            return rv;
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public IndexedDigest H_msg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] message) {
            int forsMsgBytes = ((this.A * this.K) + 7) / 8;
            int leafBits = this.H / this.D;
            int treeBits = this.H - leafBits;
            int leafBytes = (leafBits + 7) / 8;
            int treeBytes = (treeBits + 7) / 8;
            byte[] out = new byte[(forsMsgBytes + leafBytes + treeBytes)];
            this.treeDigest.update(R, 0, R.length);
            this.treeDigest.update(pkSeed, 0, pkSeed.length);
            this.treeDigest.update(pkRoot, 0, pkRoot.length);
            this.treeDigest.update(message, 0, message.length);
            this.treeDigest.doFinal(out, 0, out.length);
            byte[] treeIndexBuf = new byte[8];
            System.arraycopy(out, forsMsgBytes, treeIndexBuf, 8 - treeBytes, treeBytes);
            long treeIndex = Pack.bigEndianToLong(treeIndexBuf, 0) & (-1 >>> (64 - treeBits));
            byte[] leafIndexBuf = new byte[4];
            System.arraycopy(out, forsMsgBytes + treeBytes, leafIndexBuf, 4 - leafBytes, leafBytes);
            return new IndexedDigest(treeIndex, Pack.bigEndianToInt(leafIndexBuf, 0) & (-1 >>> (32 - leafBits)), Arrays.copyOfRange(out, 0, forsMsgBytes));
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m) {
            byte[] mTheta = m;
            if (this.robust) {
                mTheta = bitmask(pkSeed, adrs, m);
            }
            byte[] rv = new byte[this.N];
            this.treeDigest.update(pkSeed, 0, pkSeed.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.update(mTheta, 0, mTheta.length);
            this.treeDigest.doFinal(rv, 0, rv.length);
            return rv;
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs) {
            this.treeDigest.update(skSeed, 0, skSeed.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            byte[] prf = new byte[this.N];
            this.treeDigest.doFinal(prf, 0, this.N);
            return prf;
        }

        @Override // com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message) {
            this.treeDigest.update(prf, 0, prf.length);
            this.treeDigest.update(randomiser, 0, randomiser.length);
            this.treeDigest.update(message, 0, message.length);
            byte[] out = new byte[this.N];
            this.treeDigest.doFinal(out, 0, out.length);
            return out;
        }

        /* access modifiers changed from: protected */
        public byte[] bitmask(byte[] pkSeed, ADRS adrs, byte[] m) {
            byte[] mask = new byte[m.length];
            this.treeDigest.update(pkSeed, 0, pkSeed.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.doFinal(mask, 0, mask.length);
            for (int i = 0; i < m.length; i++) {
                mask[i] = (byte) (mask[i] ^ m[i]);
            }
            return mask;
        }
    }
}
