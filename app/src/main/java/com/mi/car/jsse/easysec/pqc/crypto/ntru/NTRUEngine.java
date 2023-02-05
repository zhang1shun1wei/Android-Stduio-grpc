package com.mi.car.jsse.easysec.pqc.crypto.ntru;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.IntegerPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.ProductFormPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.SparseTernaryPolynomial;
import com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.TernaryPolynomial;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class NTRUEngine implements AsymmetricBlockCipher {
    private boolean forEncryption;
    private NTRUEncryptionParameters params;
    private NTRUEncryptionPrivateKeyParameters privKey;
    private NTRUEncryptionPublicKeyParameters pubKey;
    private SecureRandom random;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public void init(boolean forEncryption2, CipherParameters parameters) {
        this.forEncryption = forEncryption2;
        if (forEncryption2) {
            if (parameters instanceof ParametersWithRandom) {
                ParametersWithRandom p = (ParametersWithRandom) parameters;
                this.random = p.getRandom();
                this.pubKey = (NTRUEncryptionPublicKeyParameters) p.getParameters();
            } else {
                this.random = CryptoServicesRegistrar.getSecureRandom();
                this.pubKey = (NTRUEncryptionPublicKeyParameters) parameters;
            }
            this.params = this.pubKey.getParameters();
            return;
        }
        this.privKey = (NTRUEncryptionPrivateKeyParameters) parameters;
        this.params = this.privKey.getParameters();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        return this.params.maxMsgLenBytes;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        return ((this.params.N * log2(this.params.q)) + 7) / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] in, int inOff, int len) throws InvalidCipherTextException {
        byte[] tmp = new byte[len];
        System.arraycopy(in, inOff, tmp, 0, len);
        if (this.forEncryption) {
            return encrypt(tmp, this.pubKey);
        }
        return decrypt(tmp, this.privKey);
    }

    private byte[] encrypt(byte[] m, NTRUEncryptionPublicKeyParameters pubKey2) {
        IntegerPolynomial pub = pubKey2.h;
        int N = this.params.N;
        int q = this.params.q;
        int maxLenBytes = this.params.maxMsgLenBytes;
        int db = this.params.db;
        int bufferLenBits = this.params.bufferLenBits;
        int dm0 = this.params.dm0;
        int pkLen = this.params.pkLen;
        int minCallsMask = this.params.minCallsMask;
        boolean hashSeed = this.params.hashSeed;
        byte[] oid = this.params.oid;
        int l = m.length;
        if (maxLenBytes > 255) {
            throw new IllegalArgumentException("llen values bigger than 1 are not supported");
        } else if (l > maxLenBytes) {
            throw new DataLengthException("Message too long: " + l + ">" + maxLenBytes);
        } else {
            while (true) {
                byte[] b = new byte[(db / 8)];
                this.random.nextBytes(b);
                byte[] p0 = new byte[((maxLenBytes + 1) - l)];
                byte[] M = new byte[(bufferLenBits / 8)];
                System.arraycopy(b, 0, M, 0, b.length);
                M[b.length] = (byte) l;
                System.arraycopy(m, 0, M, b.length + 1, m.length);
                System.arraycopy(p0, 0, M, b.length + 1 + m.length, p0.length);
                IntegerPolynomial mTrin = IntegerPolynomial.fromBinary3Sves(M, N);
                IntegerPolynomial R = generateBlindingPoly(buildSData(oid, m, l, b, copyOf(pub.toBinary(q), pkLen / 8)), M).mult(pub, q);
                IntegerPolynomial R4 = (IntegerPolynomial) R.clone();
                R4.modPositive(4);
                mTrin.add(MGF(R4.toBinary(4), N, minCallsMask, hashSeed));
                mTrin.mod3();
                if (mTrin.count(-1) >= dm0 && mTrin.count(0) >= dm0 && mTrin.count(1) >= dm0) {
                    R.add(mTrin, q);
                    R.ensurePositive(q);
                    return R.toBinary(q);
                }
            }
        }
    }

    private byte[] buildSData(byte[] oid, byte[] m, int l, byte[] b, byte[] hTrunc) {
        byte[] sData = new byte[(oid.length + l + b.length + hTrunc.length)];
        System.arraycopy(oid, 0, sData, 0, oid.length);
        System.arraycopy(m, 0, sData, oid.length, m.length);
        System.arraycopy(b, 0, sData, oid.length + m.length, b.length);
        System.arraycopy(hTrunc, 0, sData, oid.length + m.length + b.length, hTrunc.length);
        return sData;
    }

    /* access modifiers changed from: protected */
    public IntegerPolynomial encrypt(IntegerPolynomial m, TernaryPolynomial r, IntegerPolynomial pubKey2) {
        IntegerPolynomial e = r.mult(pubKey2, this.params.q);
        e.add(m, this.params.q);
        e.ensurePositive(this.params.q);
        return e;
    }

    private Polynomial generateBlindingPoly(byte[] seed, byte[] M) {
        IndexGenerator ig = new IndexGenerator(seed, this.params);
        if (this.params.polyType == 1) {
            return new ProductFormPolynomial(new SparseTernaryPolynomial(generateBlindingCoeffs(ig, this.params.dr1)), new SparseTernaryPolynomial(generateBlindingCoeffs(ig, this.params.dr2)), new SparseTernaryPolynomial(generateBlindingCoeffs(ig, this.params.dr3)));
        }
        int dr = this.params.dr;
        boolean sparse = this.params.sparse;
        int[] r = generateBlindingCoeffs(ig, dr);
        if (sparse) {
            return new SparseTernaryPolynomial(r);
        }
        return new DenseTernaryPolynomial(r);
    }

    private int[] generateBlindingCoeffs(IndexGenerator ig, int dr) {
        int[] r = new int[this.params.N];
        for (int coeff = -1; coeff <= 1; coeff += 2) {
            int t = 0;
            while (t < dr) {
                int i = ig.nextIndex();
                if (r[i] == 0) {
                    r[i] = coeff;
                    t++;
                }
            }
        }
        return r;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:25:0x0071, code lost:
        if (r5 >= r17) goto L_0x005a;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private IntegerPolynomial MGF(byte[] r16, int r17, int r18, boolean r19) {
        /*
        // Method dump skipped, instructions count: 131
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.pqc.crypto.ntru.NTRUEngine.MGF(byte[], int, int, boolean):com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.IntegerPolynomial");
    }

    private void putInt(Digest hashAlg, int counter) {
        hashAlg.update((byte) (counter >> 24));
        hashAlg.update((byte) (counter >> 16));
        hashAlg.update((byte) (counter >> 8));
        hashAlg.update((byte) counter);
    }

    private byte[] calcHash(Digest hashAlg) {
        byte[] tmp = new byte[hashAlg.getDigestSize()];
        hashAlg.doFinal(tmp, 0);
        return tmp;
    }

    private byte[] calcHash(Digest hashAlg, byte[] input) {
        byte[] tmp = new byte[hashAlg.getDigestSize()];
        hashAlg.update(input, 0, input.length);
        hashAlg.doFinal(tmp, 0);
        return tmp;
    }

    private byte[] decrypt(byte[] data, NTRUEncryptionPrivateKeyParameters privKey2) throws InvalidCipherTextException {
        Polynomial priv_t = privKey2.t;
        IntegerPolynomial priv_fp = privKey2.fp;
        IntegerPolynomial pub = privKey2.h;
        int N = this.params.N;
        int q = this.params.q;
        int db = this.params.db;
        int maxMsgLenBytes = this.params.maxMsgLenBytes;
        int dm0 = this.params.dm0;
        int pkLen = this.params.pkLen;
        int minCallsMask = this.params.minCallsMask;
        boolean hashSeed = this.params.hashSeed;
        byte[] oid = this.params.oid;
        if (maxMsgLenBytes > 255) {
            throw new DataLengthException("maxMsgLenBytes values bigger than 255 are not supported");
        }
        int bLen = db / 8;
        IntegerPolynomial e = IntegerPolynomial.fromBinary(data, N, q);
        IntegerPolynomial ci = decrypt(e, priv_t, priv_fp);
        if (ci.count(-1) < dm0) {
            throw new InvalidCipherTextException("Less than dm0 coefficients equal -1");
        } else if (ci.count(0) < dm0) {
            throw new InvalidCipherTextException("Less than dm0 coefficients equal 0");
        } else if (ci.count(1) < dm0) {
            throw new InvalidCipherTextException("Less than dm0 coefficients equal 1");
        } else {
            IntegerPolynomial cR = (IntegerPolynomial) e.clone();
            cR.sub(ci);
            cR.modPositive(q);
            IntegerPolynomial cR4 = (IntegerPolynomial) cR.clone();
            cR4.modPositive(4);
            ci.sub(MGF(cR4.toBinary(4), N, minCallsMask, hashSeed));
            ci.mod3();
            byte[] cM = ci.toBinary3Sves();
            byte[] cb = new byte[bLen];
            System.arraycopy(cM, 0, cb, 0, bLen);
            int cl = cM[bLen] & GF2Field.MASK;
            if (cl > maxMsgLenBytes) {
                throw new InvalidCipherTextException("Message too long: " + cl + ">" + maxMsgLenBytes);
            }
            byte[] cm = new byte[cl];
            System.arraycopy(cM, bLen + 1, cm, 0, cl);
            byte[] p0 = new byte[(cM.length - ((bLen + 1) + cl))];
            System.arraycopy(cM, bLen + 1 + cl, p0, 0, p0.length);
            if (!Arrays.constantTimeAreEqual(p0, new byte[p0.length])) {
                throw new InvalidCipherTextException("The message is not followed by zeroes");
            }
            IntegerPolynomial cRPrime = generateBlindingPoly(buildSData(oid, cm, cl, cb, copyOf(pub.toBinary(q), pkLen / 8)), cm).mult(pub);
            cRPrime.modPositive(q);
            if (cRPrime.equals(cR)) {
                return cm;
            }
            throw new InvalidCipherTextException("Invalid message encoding");
        }
    }

    /* access modifiers changed from: protected */
    public IntegerPolynomial decrypt(IntegerPolynomial e, Polynomial priv_t, IntegerPolynomial priv_fp) {
        IntegerPolynomial a;
        if (this.params.fastFp) {
            a = priv_t.mult(e, this.params.q);
            a.mult(3);
            a.add(e);
        } else {
            a = priv_t.mult(e, this.params.q);
        }
        a.center0(this.params.q);
        a.mod3();
        IntegerPolynomial c = this.params.fastFp ? a : new DenseTernaryPolynomial(a).mult(priv_fp, 3);
        c.center0(3);
        return c;
    }

    private byte[] copyOf(byte[] src, int len) {
        byte[] tmp = new byte[len];
        if (len >= src.length) {
            len = src.length;
        }
        System.arraycopy(src, 0, tmp, 0, len);
        return tmp;
    }

    private int log2(int value) {
        if (value == 2048) {
            return 11;
        }
        throw new IllegalStateException("log2 not fully implemented");
    }
}
