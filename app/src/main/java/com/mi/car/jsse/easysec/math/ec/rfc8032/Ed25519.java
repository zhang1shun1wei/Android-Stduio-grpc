package com.mi.car.jsse.easysec.math.ec.rfc8032;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.math.ec.rfc7748.X25519;
import com.mi.car.jsse.easysec.math.ec.rfc7748.X25519Field;
import com.mi.car.jsse.easysec.math.raw.Interleave;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public abstract class Ed25519 {
    private static final int[] B_x = {52811034, 25909283, 8072341, 50637101, 13785486, 30858332, 20483199, 20966410, 43936626, 4379245};
    private static final int[] B_y = {40265304, 26843545, 6710886, 53687091, 13421772, 40265318, 26843545, 6710886, 53687091, 13421772};
    private static final int COORD_INTS = 8;
    private static final int[] C_d = {56195235, 47411844, 25868126, 40503822, 57364, 58321048, 30416477, 31930572, 57760639, 10749657};
    private static final int[] C_d2 = {45281625, 27714825, 18181821, 13898781, 114729, 49533232, 60832955, 30306712, 48412415, 4722099};
    private static final int[] C_d4 = {23454386, 55429651, 2809210, 27797563, 229458, 31957600, 54557047, 27058993, 29715967, 9444199};
    private static final byte[] DOM2_PREFIX = {83, 105, 103, 69, 100, 50, 53, 53, 49, 57, 32, 110, 111, 32, 69, 100, 50, 53, 53, 49, 57, 32, 99, 111, 108, 108, 105, 115, 105, 111, 110, 115};
    private static final int[] L = {1559614445, 1477600026, -1560830762, 350157278, 0, 0, 0, 268435456};
    private static final int L0 = -50998291;
    private static final int L1 = 19280294;
    private static final int L2 = 127719000;
    private static final int L3 = -6428113;
    private static final int L4 = 5343;
    private static final long M08L = 255;
    private static final long M28L = 268435455;
    private static final long M32L = 4294967295L;
    private static final int[] P = {-19, -1, -1, -1, -1, -1, -1, Integer.MAX_VALUE};
    private static final int POINT_BYTES = 32;
    private static final int PRECOMP_BLOCKS = 8;
    private static final int PRECOMP_MASK = 7;
    private static final int PRECOMP_POINTS = 8;
    private static final int PRECOMP_SPACING = 8;
    private static final int PRECOMP_TEETH = 4;
    public static final int PREHASH_SIZE = 64;
    public static final int PUBLIC_KEY_SIZE = 32;
    private static final int SCALAR_BYTES = 32;
    private static final int SCALAR_INTS = 8;
    public static final int SECRET_KEY_SIZE = 32;
    public static final int SIGNATURE_SIZE = 64;
    private static final int WNAF_WIDTH_BASE = 7;
    private static int[] precompBase = null;
    private static PointExt[] precompBaseTable = null;
    private static final Object precompLock = new Object();

    public static final class Algorithm {
        public static final int Ed25519 = 0;
        public static final int Ed25519ctx = 1;
        public static final int Ed25519ph = 2;
    }

    private static class F extends X25519Field {
        private F() {
        }
    }

    /* access modifiers changed from: private */
    public static class PointAccum {
        int[] u;
        int[] v;
        int[] x;
        int[] y;
        int[] z;

        private PointAccum() {
            this.x = F.create();
            this.y = F.create();
            this.z = F.create();
            this.u = F.create();
            this.v = F.create();
        }
    }

    /* access modifiers changed from: private */
    public static class PointAffine {
        int[] x;
        int[] y;

        private PointAffine() {
            this.x = F.create();
            this.y = F.create();
        }
    }

    /* access modifiers changed from: private */
    public static class PointExt {
        int[] t;
        int[] x;
        int[] y;
        int[] z;

        private PointExt() {
            this.x = F.create();
            this.y = F.create();
            this.z = F.create();
            this.t = F.create();
        }
    }

    /* access modifiers changed from: private */
    public static class PointPrecomp {
        int[] xyd;
        int[] ymx_h;
        int[] ypx_h;

        private PointPrecomp() {
            this.ypx_h = F.create();
            this.ymx_h = F.create();
            this.xyd = F.create();
        }
    }

    private static byte[] calculateS(byte[] r, byte[] k, byte[] s) {
        int[] t = new int[16];
        decodeScalar(r, 0, t);
        int[] u = new int[8];
        decodeScalar(k, 0, u);
        int[] v = new int[8];
        decodeScalar(s, 0, v);
        Nat256.mulAddTo(u, v, t);
        byte[] result = new byte[64];
        for (int i = 0; i < t.length; i++) {
            encode32(t[i], result, i * 4);
        }
        return reduceScalar(result);
    }

    private static boolean checkContextVar(byte[] ctx, byte phflag) {
        return (ctx == null && phflag == 0) || (ctx != null && ctx.length < 256);
    }

    private static int checkPoint(int[] x, int[] y) {
        int[] t = F.create();
        int[] u = F.create();
        int[] v = F.create();
        F.sqr(x, u);
        F.sqr(y, v);
        F.mul(u, v, t);
        F.sub(v, u, v);
        F.mul(t, C_d, t);
        F.addOne(t);
        F.sub(t, v, t);
        F.normalize(t);
        return F.isZero(t);
    }

    private static int checkPoint(int[] x, int[] y, int[] z) {
        int[] t = F.create();
        int[] u = F.create();
        int[] v = F.create();
        int[] w = F.create();
        F.sqr(x, u);
        F.sqr(y, v);
        F.sqr(z, w);
        F.mul(u, v, t);
        F.sub(v, u, v);
        F.mul(v, w, v);
        F.sqr(w, w);
        F.mul(t, C_d, t);
        F.add(t, w, t);
        F.sub(t, v, t);
        F.normalize(t);
        return F.isZero(t);
    }

    private static boolean checkPointVar(byte[] p) {
        int[] t = new int[8];
        decode32(p, 0, t, 0, 8);
        t[7] = t[7] & Integer.MAX_VALUE;
        if (!Nat256.gte(t, P)) {
            return true;
        }
        return false;
    }

    private static boolean checkScalarVar(byte[] s, int[] n) {
        decodeScalar(s, 0, n);
        if (!Nat256.gte(n, L)) {
            return true;
        }
        return false;
    }

    private static byte[] copy(byte[] buf, int off, int len) {
        byte[] result = new byte[len];
        System.arraycopy(buf, off, result, 0, len);
        return result;
    }

    private static Digest createDigest() {
        return new SHA512Digest();
    }

    public static Digest createPrehash() {
        return createDigest();
    }

    private static int decode24(byte[] bs, int off) {
        int off2 = off + 1;
        return (bs[off] & 255) | ((bs[off2] & 255) << 8) | ((bs[off2 + 1] & 255) << 16);
    }

    private static int decode32(byte[] bs, int off) {
        int off2 = off + 1;
        int off3 = off2 + 1;
        return (bs[off] & 255) | ((bs[off2] & 255) << 8) | ((bs[off3] & 255) << 16) | (bs[off3 + 1] << 24);
    }

    private static void decode32(byte[] bs, int bsOff, int[] n, int nOff, int nLen) {
        for (int i = 0; i < nLen; i++) {
            n[nOff + i] = decode32(bs, (i * 4) + bsOff);
        }
    }

    private static boolean decodePointVar(byte[] p, int pOff, boolean negate, PointAffine r) {
        boolean z = false;
        byte[] py = copy(p, pOff, 32);
        if (!checkPointVar(py)) {
            return false;
        }
        int x_0 = (py[31] & 128) >>> 7;
        py[31] = (byte) (py[31] & Byte.MAX_VALUE);
        F.decode(py, 0, r.y);
        int[] u = F.create();
        int[] v = F.create();
        F.sqr(r.y, u);
        F.mul(C_d, u, v);
        F.subOne(u);
        F.addOne(v);
        if (!F.sqrtRatioVar(u, v, r.x)) {
            return false;
        }
        F.normalize(r.x);
        if (x_0 == 1 && F.isZeroVar(r.x)) {
            return false;
        }
        if (x_0 != (r.x[0] & 1)) {
            z = true;
        }
        if (z ^ negate) {
            F.negate(r.x, r.x);
        }
        return true;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n) {
        decode32(k, kOff, n, 0, 8);
    }

    private static void dom2(Digest d, byte phflag, byte[] ctx) {
        if (ctx != null) {
            int n = DOM2_PREFIX.length;
            byte[] t = new byte[(n + 2 + ctx.length)];
            System.arraycopy(DOM2_PREFIX, 0, t, 0, n);
            t[n] = phflag;
            t[n + 1] = (byte) ctx.length;
            System.arraycopy(ctx, 0, t, n + 2, ctx.length);
            d.update(t, 0, t.length);
        }
    }

    private static void encode24(int n, byte[] bs, int off) {
        bs[off] = (byte) n;
        int off2 = off + 1;
        bs[off2] = (byte) (n >>> 8);
        bs[off2 + 1] = (byte) (n >>> 16);
    }

    private static void encode32(int n, byte[] bs, int off) {
        bs[off] = (byte) n;
        int off2 = off + 1;
        bs[off2] = (byte) (n >>> 8);
        int off3 = off2 + 1;
        bs[off3] = (byte) (n >>> 16);
        bs[off3 + 1] = (byte) (n >>> 24);
    }

    private static void encode56(long n, byte[] bs, int off) {
        encode32((int) n, bs, off);
        encode24((int) (n >>> 32), bs, off + 4);
    }

    private static int encodePoint(PointAccum p, byte[] r, int rOff) {
        int[] x = F.create();
        int[] y = F.create();
        F.inv(p.z, y);
        F.mul(p.x, y, x);
        F.mul(p.y, y, y);
        F.normalize(x);
        F.normalize(y);
        int result = checkPoint(x, y);
        F.encode(y, r, rOff);
        int i = (rOff + 32) - 1;
        r[i] = (byte) (r[i] | ((x[0] & 1) << 7));
        return result;
    }

    public static void generatePrivateKey(SecureRandom random, byte[] k) {
        random.nextBytes(k);
    }

    public static void generatePublicKey(byte[] sk, int skOff, byte[] pk, int pkOff) {
        Digest d = createDigest();
        byte[] h = new byte[d.getDigestSize()];
        d.update(sk, skOff, 32);
        d.doFinal(h, 0);
        byte[] s = new byte[32];
        pruneScalar(h, 0, s);
        scalarMultBaseEncoded(s, pk, pkOff);
    }

    private static int getWindow4(int[] x, int n) {
        return (x[n >>> 3] >>> ((n & 7) << 2)) & 15;
    }

    private static byte[] getWnafVar(int[] n, int width) {
        int[] t = new int[16];
        int tPos = t.length;
        int c = 0;
        int i = 8;
        while (true) {
            i--;
            if (i < 0) {
                break;
            }
            int next = n[i];
            int tPos2 = tPos - 1;
            t[tPos2] = (next >>> 16) | (c << 16);
            tPos = tPos2 - 1;
            c = next;
            t[tPos] = next;
        }
        byte[] ws = new byte[253];
        int lead = 32 - width;
        int j = 0;
        int carry = 0;
        int i2 = 0;
        while (i2 < t.length) {
            int word = t[i2];
            while (j < 16) {
                int word16 = word >>> j;
                if ((word16 & 1) == carry) {
                    j++;
                } else {
                    int digit = (word16 | 1) << lead;
                    carry = digit >>> 31;
                    ws[(i2 << 4) + j] = (byte) (digit >> lead);
                    j += width;
                }
            }
            i2++;
            j -= 16;
        }
        return ws;
    }

    private static void implSign(Digest d, byte[] h, byte[] s, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        dom2(d, phflag, ctx);
        d.update(h, 32, 32);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);
        byte[] r = reduceScalar(h);
        byte[] R = new byte[32];
        scalarMultBaseEncoded(r, R, 0);
        dom2(d, phflag, ctx);
        d.update(R, 0, 32);
        d.update(pk, pkOff, 32);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);
        byte[] S = calculateS(r, reduceScalar(h), s);
        System.arraycopy(R, 0, sig, sigOff, 32);
        System.arraycopy(S, 0, sig, sigOff + 32, 32);
    }

    private static void implSign(byte[] sk, int skOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        if (!checkContextVar(ctx, phflag)) {
            throw new IllegalArgumentException("ctx");
        }
        Digest d = createDigest();
        byte[] h = new byte[d.getDigestSize()];
        d.update(sk, skOff, 32);
        d.doFinal(h, 0);
        byte[] s = new byte[32];
        pruneScalar(h, 0, s);
        byte[] pk = new byte[32];
        scalarMultBaseEncoded(s, pk, 0);
        implSign(d, h, s, pk, 0, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    private static void implSign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        if (!checkContextVar(ctx, phflag)) {
            throw new IllegalArgumentException("ctx");
        }
        Digest d = createDigest();
        byte[] h = new byte[d.getDigestSize()];
        d.update(sk, skOff, 32);
        d.doFinal(h, 0);
        byte[] s = new byte[32];
        pruneScalar(h, 0, s);
        implSign(d, h, s, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    private static boolean implVerify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen) {
        if (!checkContextVar(ctx, phflag)) {
            throw new IllegalArgumentException("ctx");
        }
        byte[] R = copy(sig, sigOff, 32);
        byte[] S = copy(sig, sigOff + 32, 32);
        if (!checkPointVar(R)) {
            return false;
        }
        int[] nS = new int[8];
        if (!checkScalarVar(S, nS)) {
            return false;
        }
        PointAffine pA = new PointAffine();
        if (!decodePointVar(pk, pkOff, true, pA)) {
            return false;
        }
        Digest d = createDigest();
        byte[] h = new byte[d.getDigestSize()];
        dom2(d, phflag, ctx);
        d.update(R, 0, 32);
        d.update(pk, pkOff, 32);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0);
        int[] nA = new int[8];
        decodeScalar(reduceScalar(h), 0, nA);
        PointAccum pR = new PointAccum();
        scalarMultStrausVar(nS, nA, pA, pR);
        byte[] check = new byte[32];
        return encodePoint(pR, check, 0) != 0 && Arrays.areEqual(check, R);
    }

    private static boolean isNeutralElementVar(int[] x, int[] y) {
        return F.isZeroVar(x) && F.isOneVar(y);
    }

    private static boolean isNeutralElementVar(int[] x, int[] y, int[] z) {
        return F.isZeroVar(x) && F.areEqualVar(y, z);
    }

    private static void pointAdd(PointExt p, PointAccum r) {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = r.u;
        int[] f = F.create();
        int[] g = F.create();
        int[] h = r.v;
        F.apm(r.y, r.x, b, a);
        F.apm(p.y, p.x, d, c);
        F.mul(a, c, a);
        F.mul(b, d, b);
        F.mul(r.u, r.v, c);
        F.mul(c, p.t, c);
        F.mul(c, C_d2, c);
        F.mul(r.z, p.z, d);
        F.add(d, d, d);
        F.apm(b, a, h, e);
        F.apm(d, c, g, f);
        F.carry(g);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointAdd(PointExt p, PointExt r) {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = F.create();
        int[] f = F.create();
        int[] g = F.create();
        int[] h = F.create();
        F.apm(p.y, p.x, b, a);
        F.apm(r.y, r.x, d, c);
        F.mul(a, c, a);
        F.mul(b, d, b);
        F.mul(p.t, r.t, c);
        F.mul(c, C_d2, c);
        F.mul(p.z, r.z, d);
        F.add(d, d, d);
        F.apm(b, a, h, e);
        F.apm(d, c, g, f);
        F.carry(g);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
        F.mul(e, h, r.t);
    }

    private static void pointAddVar(boolean negate, PointExt p, PointAccum r) {
        int[] nc;
        int[] nd;
        int[] nf;
        int[] ng;
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = r.u;
        int[] f = F.create();
        int[] g = F.create();
        int[] h = r.v;
        if (negate) {
            nc = d;
            nd = c;
            nf = g;
            ng = f;
        } else {
            nc = c;
            nd = d;
            nf = f;
            ng = g;
        }
        F.apm(r.y, r.x, b, a);
        F.apm(p.y, p.x, nd, nc);
        F.mul(a, c, a);
        F.mul(b, d, b);
        F.mul(r.u, r.v, c);
        F.mul(c, p.t, c);
        F.mul(c, C_d2, c);
        F.mul(r.z, p.z, d);
        F.add(d, d, d);
        F.apm(b, a, h, e);
        F.apm(d, c, ng, nf);
        F.carry(ng);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointAddVar(boolean negate, PointExt p, PointExt q, PointExt r) {
        int[] nc;
        int[] nd;
        int[] nf;
        int[] ng;
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = F.create();
        int[] f = F.create();
        int[] g = F.create();
        int[] h = F.create();
        if (negate) {
            nc = d;
            nd = c;
            nf = g;
            ng = f;
        } else {
            nc = c;
            nd = d;
            nf = f;
            ng = g;
        }
        F.apm(p.y, p.x, b, a);
        F.apm(q.y, q.x, nd, nc);
        F.mul(a, c, a);
        F.mul(b, d, b);
        F.mul(p.t, q.t, c);
        F.mul(c, C_d2, c);
        F.mul(p.z, q.z, d);
        F.add(d, d, d);
        F.apm(b, a, h, e);
        F.apm(d, c, ng, nf);
        F.carry(ng);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
        F.mul(e, h, r.t);
    }

    private static void pointAddPrecomp(PointPrecomp p, PointAccum r) {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] e = r.u;
        int[] f = F.create();
        int[] g = F.create();
        int[] h = r.v;
        F.apm(r.y, r.x, b, a);
        F.mul(a, p.ymx_h, a);
        F.mul(b, p.ypx_h, b);
        F.mul(r.u, r.v, c);
        F.mul(c, p.xyd, c);
        F.apm(b, a, h, e);
        F.apm(r.z, c, g, f);
        F.carry(g);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
    }

    private static PointExt pointCopy(PointAccum p) {
        PointExt r = new PointExt();
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        F.copy(p.z, 0, r.z, 0);
        F.mul(p.u, p.v, r.t);
        return r;
    }

    private static PointExt pointCopy(PointAffine p) {
        PointExt r = new PointExt();
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        pointExtendXY(r);
        return r;
    }

    private static PointExt pointCopy(PointExt p) {
        PointExt r = new PointExt();
        pointCopy(p, r);
        return r;
    }

    private static void pointCopy(PointExt p, PointExt r) {
        F.copy(p.x, 0, r.x, 0);
        F.copy(p.y, 0, r.y, 0);
        F.copy(p.z, 0, r.z, 0);
        F.copy(p.t, 0, r.t, 0);
    }

    private static void pointDouble(PointAccum r) {
        int[] a = F.create();
        int[] b = F.create();
        int[] c = F.create();
        int[] e = r.u;
        int[] f = F.create();
        int[] g = F.create();
        int[] h = r.v;
        F.sqr(r.x, a);
        F.sqr(r.y, b);
        F.sqr(r.z, c);
        F.add(c, c, c);
        F.apm(a, b, h, g);
        F.add(r.x, r.y, e);
        F.sqr(e, e);
        F.sub(h, e, e);
        F.add(c, g, f);
        F.carry(f);
        F.mul(e, f, r.x);
        F.mul(g, h, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointExtendXY(PointAccum p) {
        F.one(p.z);
        F.copy(p.x, 0, p.u, 0);
        F.copy(p.y, 0, p.v, 0);
    }

    private static void pointExtendXY(PointExt p) {
        F.one(p.z);
        F.mul(p.x, p.y, p.t);
    }

    private static void pointLookup(int block, int index, PointPrecomp p) {
        int off = block * 8 * 3 * 10;
        for (int i = 0; i < 8; i++) {
            int cond = ((i ^ index) - 1) >> 31;
            F.cmov(cond, precompBase, off, p.ypx_h, 0);
            int off2 = off + 10;
            F.cmov(cond, precompBase, off2, p.ymx_h, 0);
            int off3 = off2 + 10;
            F.cmov(cond, precompBase, off3, p.xyd, 0);
            off = off3 + 10;
        }
    }

    private static void pointLookup(int[] x, int n, int[] table, PointExt r) {
        int w = getWindow4(x, n);
        int sign = (w >>> 3) ^ 1;
        int abs = ((-sign) ^ w) & 7;
        int off = 0;
        for (int i = 0; i < 8; i++) {
            int cond = ((i ^ abs) - 1) >> 31;
            F.cmov(cond, table, off, r.x, 0);
            int off2 = off + 10;
            F.cmov(cond, table, off2, r.y, 0);
            int off3 = off2 + 10;
            F.cmov(cond, table, off3, r.z, 0);
            int off4 = off3 + 10;
            F.cmov(cond, table, off4, r.t, 0);
            off = off4 + 10;
        }
        F.cnegate(sign, r.x);
        F.cnegate(sign, r.t);
    }

    private static int[] pointPrecompute(PointAffine p, int count) {
        PointExt q = pointCopy(p);
        PointExt d = pointCopy(q);
        pointAdd(q, d);
        int[] table = F.createTable(count * 4);
        int off = 0;
        int i = 0;
        while (true) {
            F.copy(q.x, 0, table, off);
            int off2 = off + 10;
            F.copy(q.y, 0, table, off2);
            int off3 = off2 + 10;
            F.copy(q.z, 0, table, off3);
            int off4 = off3 + 10;
            F.copy(q.t, 0, table, off4);
            off = off4 + 10;
            i++;
            if (i == count) {
                return table;
            }
            pointAdd(d, q);
        }
    }

    private static PointExt[] pointPrecomputeVar(PointExt p, int count) {
        PointExt d = new PointExt();
        pointAddVar(false, p, p, d);
        PointExt[] table = new PointExt[count];
        table[0] = pointCopy(p);
        for (int i = 1; i < count; i++) {
            PointExt pointExt = table[i - 1];
            PointExt pointExt2 = new PointExt();
            table[i] = pointExt2;
            pointAddVar(false, pointExt, d, pointExt2);
        }
        return table;
    }

    private static void pointSetNeutral(PointAccum p) {
        F.zero(p.x);
        F.one(p.y);
        F.one(p.z);
        F.zero(p.u);
        F.one(p.v);
    }

    private static void pointSetNeutral(PointExt p) {
        F.zero(p.x);
        F.one(p.y);
        F.one(p.z);
        F.zero(p.t);
    }

    /* JADX INFO: Multiple debug info for r20v4 int[]: [D('t' int), D('t' int[])] */
    public static void precompute() {
        synchronized (precompLock) {
            if (precompBase == null) {
                PointExt b = new PointExt();
                F.copy(B_x, 0, b.x, 0);
                F.copy(B_y, 0, b.y, 0);
                pointExtendXY(b);
                precompBaseTable = pointPrecomputeVar(b, 32);
                PointAccum p = new PointAccum();
                F.copy(B_x, 0, p.x, 0);
                F.copy(B_y, 0, p.y, 0);
                pointExtendXY(p);
                precompBase = F.createTable(BERTags.PRIVATE);
                int off = 0;
                for (int b2 = 0; b2 < 8; b2++) {
                    PointExt[] ds = new PointExt[4];
                    PointExt sum = new PointExt();
                    pointSetNeutral(sum);
                    for (int t = 0; t < 4; t++) {
                        pointAddVar(true, sum, pointCopy(p), sum);
                        pointDouble(p);
                        ds[t] = pointCopy(p);
                        if (b2 + t != 10) {
                            for (int s = 1; s < 8; s++) {
                                pointDouble(p);
                            }
                        }
                    }
                    PointExt[] points = new PointExt[8];
                    points[0] = sum;
                    int k = 0 + 1;
                    for (int t2 = 0; t2 < 3; t2++) {
                        int size = 1 << t2;
                        int j = 0;
                        while (j < size) {
                            PointExt pointExt = points[k - size];
                            PointExt pointExt2 = ds[t2];
                            PointExt pointExt3 = new PointExt();
                            points[k] = pointExt3;
                            pointAddVar(false, pointExt, pointExt2, pointExt3);
                            j++;
                            k++;
                        }
                    }
                    int[] cs = F.createTable(8);
                    int[] u = F.create();
                    F.copy(points[0].z, 0, u, 0);
                    F.copy(u, 0, cs, 0);
                    int i = 0;
                    while (true) {
                        i++;
                        if (i >= 8) {
                            break;
                        }
                        F.mul(u, points[i].z, u);
                        F.copy(u, 0, cs, i * 10);
                    }
                    F.add(u, u, u);
                    F.invVar(u, u);
                    int[] t3 = F.create();
                    int i2 = i - 1;
                    while (i2 > 0) {
                        int i3 = i2 - 1;
                        F.copy(cs, i3 * 10, t3, 0);
                        F.mul(t3, u, t3);
                        F.copy(t3, 0, cs, i2 * 10);
                        F.mul(u, points[i2].z, u);
                        i2 = i3;
                    }
                    F.copy(u, 0, cs, 0);
                    for (int i4 = 0; i4 < 8; i4++) {
                        PointExt q = points[i4];
                        int[] x = F.create();
                        int[] y = F.create();
                        F.copy(cs, i4 * 10, y, 0);
                        F.mul(q.x, y, x);
                        F.mul(q.y, y, y);
                        PointPrecomp r = new PointPrecomp();
                        F.apm(y, x, r.ypx_h, r.ymx_h);
                        F.mul(x, y, r.xyd);
                        F.mul(r.xyd, C_d4, r.xyd);
                        F.normalize(r.ypx_h);
                        F.normalize(r.ymx_h);
                        F.copy(r.ypx_h, 0, precompBase, off);
                        int off2 = off + 10;
                        F.copy(r.ymx_h, 0, precompBase, off2);
                        int off3 = off2 + 10;
                        F.copy(r.xyd, 0, precompBase, off3);
                        off = off3 + 10;
                    }
                }
            }
        }
    }

    private static void pruneScalar(byte[] n, int nOff, byte[] r) {
        System.arraycopy(n, nOff, r, 0, 32);
        r[0] = (byte) (r[0] & 248);
        r[31] = (byte) (r[31] & Byte.MAX_VALUE);
        r[31] = (byte) (r[31] | 64);
    }

    private static byte[] reduceScalar(byte[] n) {
        long x00 = ((long) decode32(n, 0)) & M32L;
        long x01 = ((long) (decode24(n, 4) << 4)) & M32L;
        long x02 = ((long) decode32(n, 7)) & M32L;
        long x03 = ((long) (decode24(n, 11) << 4)) & M32L;
        long x04 = ((long) decode32(n, 14)) & M32L;
        long x05 = ((long) (decode24(n, 18) << 4)) & M32L;
        long x06 = ((long) decode32(n, 21)) & M32L;
        long x07 = ((long) (decode24(n, 25) << 4)) & M32L;
        long x08 = ((long) decode32(n, 28)) & M32L;
        long x09 = ((long) (decode24(n, 32) << 4)) & M32L;
        long x10 = ((long) decode32(n, 35)) & M32L;
        long x11 = ((long) (decode24(n, 39) << 4)) & M32L;
        long x12 = ((long) decode32(n, 42)) & M32L;
        long x13 = ((long) (decode24(n, 46) << 4)) & M32L;
        long x14 = ((long) decode32(n, 49)) & M32L;
        long x15 = ((long) (decode24(n, 53) << 4)) & M32L;
        long x16 = ((long) decode32(n, 56)) & M32L;
        long x17 = ((long) (decode24(n, 60) << 4)) & M32L;
        long x18 = ((long) n[63]) & M08L;
        long x172 = x17 + (x16 >> 28);
        long x162 = x16 & M28L;
        long x122 = (x12 - (-6428113 * x18)) - (5343 * x172);
        long x112 = ((x11 - (127719000 * x18)) - (-6428113 * x172)) - (5343 * x162);
        long x152 = x15 + (x14 >> 28);
        long x142 = x14 & M28L;
        long x102 = (((x10 - (19280294 * x18)) - (127719000 * x172)) - (-6428113 * x162)) - (5343 * x152);
        long x092 = ((((x09 - (-50998291 * x18)) - (19280294 * x172)) - (127719000 * x162)) - (-6428113 * x152)) - (5343 * x142);
        long x132 = (x13 - (5343 * x18)) + (x122 >> 28);
        long x123 = (x122 & M28L) + (x112 >> 28);
        long x072 = ((((x07 - (-50998291 * x162)) - (19280294 * x152)) - (127719000 * x142)) - (-6428113 * x132)) - (5343 * x123);
        long x113 = (x112 & M28L) + (x102 >> 28);
        long x103 = (x102 & M28L) + (x092 >> 28);
        long x093 = x092 & M28L;
        long x082 = (((((x08 - (-50998291 * x172)) - (19280294 * x162)) - (127719000 * x152)) - (-6428113 * x142)) - (5343 * x132)) + (x072 >> 28);
        long x073 = x072 & M28L;
        long x083 = x082 & M28L;
        long t = x083 >>> 27;
        long x094 = x093 + (x082 >> 28) + t;
        long x002 = x00 - (-50998291 * x094);
        long x012 = ((x01 - (-50998291 * x103)) - (19280294 * x094)) + (x002 >> 28);
        long x003 = x002 & M28L;
        long x022 = (((x02 - (-50998291 * x113)) - (19280294 * x103)) - (127719000 * x094)) + (x012 >> 28);
        long x013 = x012 & M28L;
        long x032 = ((((x03 - (-50998291 * x123)) - (19280294 * x113)) - (127719000 * x103)) - (-6428113 * x094)) + (x022 >> 28);
        long x023 = x022 & M28L;
        long x042 = (((((x04 - (-50998291 * x132)) - (19280294 * x123)) - (127719000 * x113)) - (-6428113 * x103)) - (5343 * x094)) + (x032 >> 28);
        long x033 = x032 & M28L;
        long x052 = (((((x05 - (-50998291 * x142)) - (19280294 * x132)) - (127719000 * x123)) - (-6428113 * x113)) - (5343 * x103)) + (x042 >> 28);
        long x043 = x042 & M28L;
        long x062 = (((((x06 - (-50998291 * x152)) - (19280294 * x142)) - (127719000 * x132)) - (-6428113 * x123)) - (5343 * x113)) + (x052 >> 28);
        long x053 = x052 & M28L;
        long x074 = x073 + (x062 >> 28);
        long x063 = x062 & M28L;
        long x084 = x083 + (x074 >> 28);
        long x075 = x074 & M28L;
        long x095 = x084 >> 28;
        long x085 = x084 & M28L;
        long x096 = x095 - t;
        long x004 = x003 + (-50998291 & x096);
        long x014 = x013 + (19280294 & x096) + (x004 >> 28);
        long x005 = x004 & M28L;
        long x024 = x023 + (127719000 & x096) + (x014 >> 28);
        long x015 = x014 & M28L;
        long x034 = x033 + (-6428113 & x096) + (x024 >> 28);
        long x025 = x024 & M28L;
        long x044 = x043 + (5343 & x096) + (x034 >> 28);
        long x035 = x034 & M28L;
        long x054 = x053 + (x044 >> 28);
        long x045 = x044 & M28L;
        long x064 = x063 + (x054 >> 28);
        long x055 = x054 & M28L;
        long x076 = x075 + (x064 >> 28);
        long x065 = x064 & M28L;
        long x086 = x085 + (x076 >> 28);
        long x077 = x076 & M28L;
        byte[] r = new byte[32];
        encode56((x015 << 28) | x005, r, 0);
        encode56((x035 << 28) | x025, r, 7);
        encode56((x055 << 28) | x045, r, 14);
        encode56((x077 << 28) | x065, r, 21);
        encode32((int) x086, r, 28);
        return r;
    }

    private static void scalarMult(byte[] k, PointAffine p, PointAccum r) {
        int[] n = new int[8];
        decodeScalar(k, 0, n);
        Nat.cadd(8, (n[0] ^ -1) & 1, n, L, n);
        Nat.shiftDownBit(8, n, 1);
        int[] table = pointPrecompute(p, 8);
        PointExt q = new PointExt();
        pointSetNeutral(r);
        int w = 63;
        while (true) {
            pointLookup(n, w, table, q);
            pointAdd(q, r);
            w--;
            if (w >= 0) {
                for (int i = 0; i < 4; i++) {
                    pointDouble(r);
                }
            } else {
                return;
            }
        }
    }

    private static void scalarMultBase(byte[] k, PointAccum r) {
        precompute();
        int[] n = new int[8];
        decodeScalar(k, 0, n);
        Nat.cadd(8, (n[0] ^ -1) & 1, n, L, n);
        Nat.shiftDownBit(8, n, 1);
        for (int i = 0; i < 8; i++) {
            n[i] = Interleave.shuffle2(n[i]);
        }
        PointPrecomp p = new PointPrecomp();
        pointSetNeutral(r);
        int cOff = 28;
        while (true) {
            for (int b = 0; b < 8; b++) {
                int w = n[b] >>> cOff;
                int sign = (w >>> 3) & 1;
                pointLookup(b, ((-sign) ^ w) & 7, p);
                F.cswap(sign, p.ypx_h, p.ymx_h);
                F.cnegate(sign, p.xyd);
                pointAddPrecomp(p, r);
            }
            cOff -= 4;
            if (cOff >= 0) {
                pointDouble(r);
            } else {
                return;
            }
        }
    }

    private static void scalarMultBaseEncoded(byte[] k, byte[] r, int rOff) {
        PointAccum p = new PointAccum();
        scalarMultBase(k, p);
        if (encodePoint(p, r, rOff) == 0) {
            throw new IllegalStateException();
        }
    }

    public static void scalarMultBaseYZ(X25519.Friend friend, byte[] k, int kOff, int[] y, int[] z) {
        if (friend == null) {
            throw new NullPointerException("This method is only for use by X25519");
        }
        byte[] n = new byte[32];
        pruneScalar(k, kOff, n);
        PointAccum p = new PointAccum();
        scalarMultBase(n, p);
        if (checkPoint(p.x, p.y, p.z) == 0) {
            throw new IllegalStateException();
        }
        F.copy(p.y, 0, y, 0);
        F.copy(p.z, 0, z, 0);
    }

    private static void scalarMultOrderVar(PointAffine p, PointAccum r) {
        byte[] ws_p = getWnafVar(L, 5);
        PointExt[] tp = pointPrecomputeVar(pointCopy(p), 8);
        pointSetNeutral(r);
        int bit = 252;
        while (true) {
            byte b = ws_p[bit];
            if (b != 0) {
                int sign = b >> 31;
                pointAddVar(sign != 0, tp[(b ^ sign) >>> 1], r);
            }
            bit--;
            if (bit >= 0) {
                pointDouble(r);
            } else {
                return;
            }
        }
    }

    private static void scalarMultStrausVar(int[] nb, int[] np, PointAffine p, PointAccum r) {
        precompute();
        byte[] ws_b = getWnafVar(nb, 7);
        byte[] ws_p = getWnafVar(np, 5);
        PointExt[] tp = pointPrecomputeVar(pointCopy(p), 8);
        pointSetNeutral(r);
        int bit = 252;
        while (true) {
            byte b = ws_b[bit];
            if (b != 0) {
                int sign = b >> 31;
                pointAddVar(sign != 0, precompBaseTable[(b ^ sign) >>> 1], r);
            }
            byte b2 = ws_p[bit];
            if (b2 != 0) {
                int sign2 = b2 >> 31;
                pointAddVar(sign2 != 0, tp[(b2 ^ sign2) >>> 1], r);
            }
            bit--;
            if (bit >= 0) {
                pointDouble(r);
            } else {
                return;
            }
        }
    }

    public static void sign(byte[] sk, int skOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        implSign(sk, skOff, null, (byte) 0, m, mOff, mLen, sig, sigOff);
    }

    public static void sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        implSign(sk, skOff, pk, pkOff, null, (byte) 0, m, mOff, mLen, sig, sigOff);
    }

    public static void sign(byte[] sk, int skOff, byte[] ctx, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        implSign(sk, skOff, ctx, (byte) 0, m, mOff, mLen, sig, sigOff);
    }

    public static void sign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        implSign(sk, skOff, pk, pkOff, ctx, (byte) 0, m, mOff, mLen, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] ctx, byte[] ph, int phOff, byte[] sig, int sigOff) {
        implSign(sk, skOff, ctx, (byte) 1, ph, phOff, 64, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff, byte[] sig, int sigOff) {
        implSign(sk, skOff, pk, pkOff, ctx, (byte) 1, ph, phOff, 64, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] ctx, Digest ph, byte[] sig, int sigOff) {
        byte[] m = new byte[64];
        if (64 != ph.doFinal(m, 0)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(sk, skOff, ctx, (byte) 1, m, 0, m.length, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, Digest ph, byte[] sig, int sigOff) {
        byte[] m = new byte[64];
        if (64 != ph.doFinal(m, 0)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(sk, skOff, pk, pkOff, ctx, (byte) 1, m, 0, m.length, sig, sigOff);
    }

    public static boolean validatePublicKeyFull(byte[] pk, int pkOff) {
        PointAffine p = new PointAffine();
        if (!decodePointVar(pk, pkOff, false, p)) {
            return false;
        }
        F.normalize(p.x);
        F.normalize(p.y);
        if (isNeutralElementVar(p.x, p.y)) {
            return false;
        }
        PointAccum r = new PointAccum();
        scalarMultOrderVar(p, r);
        F.normalize(r.x);
        F.normalize(r.y);
        F.normalize(r.z);
        return isNeutralElementVar(r.x, r.y, r.z);
    }

    public static boolean validatePublicKeyPartial(byte[] pk, int pkOff) {
        return decodePointVar(pk, pkOff, false, new PointAffine());
    }

    public static boolean verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen) {
        return implVerify(sig, sigOff, pk, pkOff, null, (byte) 0, m, mOff, mLen);
    }

    public static boolean verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen) {
        return implVerify(sig, sigOff, pk, pkOff, ctx, (byte) 0, m, mOff, mLen);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff) {
        return implVerify(sig, sigOff, pk, pkOff, ctx, (byte) 1, ph, phOff, 64);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, Digest ph) {
        byte[] m = new byte[64];
        if (64 == ph.doFinal(m, 0)) {
            return implVerify(sig, sigOff, pk, pkOff, ctx, (byte) 1, m, 0, m.length);
        }
        throw new IllegalArgumentException("ph");
    }
}
