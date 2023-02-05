package com.mi.car.jsse.easysec.math.ec.rfc8032;

import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.math.ec.rfc7748.X448;
import com.mi.car.jsse.easysec.math.ec.rfc7748.X448Field;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public abstract class Ed448 {
    private static final int[] B_x = {118276190, 40534716, 9670182, 135141552, 85017403, 259173222, 68333082, 171784774, 174973732, 15824510, 73756743, 57518561, 94773951, 248652241, 107736333, 82941708};
    private static final int[] B_y = {36764180, 8885695, 130592152, 20104429, 163904957, 30304195, 121295871, 5901357, 125344798, 171541512, 175338348, 209069246, 3626697, 38307682, 24032956, 110359655};
    private static final int COORD_INTS = 14;
    private static final int C_d = -39081;
    private static final byte[] DOM4_PREFIX = {83, 105, 103, 69, 100, 52, 52, 56};
    private static final int[] L = {-1420278541, 595116690, -1916432555, 560775794, -1361693040, -1001465015, 2093622249, -1, -1, -1, -1, -1, -1, 1073741823};
    private static final int L4_0 = 43969588;
    private static final int L4_1 = 30366549;
    private static final int L4_2 = 163752818;
    private static final int L4_3 = 258169998;
    private static final int L4_4 = 96434764;
    private static final int L4_5 = 227822194;
    private static final int L4_6 = 149865618;
    private static final int L4_7 = 550336261;
    private static final int L_0 = 78101261;
    private static final int L_1 = 141809365;
    private static final int L_2 = 175155932;
    private static final int L_3 = 64542499;
    private static final int L_4 = 158326419;
    private static final int L_5 = 191173276;
    private static final int L_6 = 104575268;
    private static final int L_7 = 137584065;
    private static final long M26L = 67108863;
    private static final long M28L = 268435455;
    private static final long M32L = 4294967295L;
    private static final int[] P = {-1, -1, -1, -1, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1};
    private static final int POINT_BYTES = 57;
    private static final int PRECOMP_BLOCKS = 5;
    private static final int PRECOMP_MASK = 15;
    private static final int PRECOMP_POINTS = 16;
    private static final int PRECOMP_RANGE = 450;
    private static final int PRECOMP_SPACING = 18;
    private static final int PRECOMP_TEETH = 5;
    public static final int PREHASH_SIZE = 64;
    public static final int PUBLIC_KEY_SIZE = 57;
    private static final int SCALAR_BYTES = 57;
    private static final int SCALAR_INTS = 14;
    public static final int SECRET_KEY_SIZE = 57;
    public static final int SIGNATURE_SIZE = 114;
    private static final int WNAF_WIDTH_BASE = 7;
    private static int[] precompBase = null;
    private static PointExt[] precompBaseTable = null;
    private static final Object precompLock = new Object();

    public static final class Algorithm {
        public static final int Ed448 = 0;
        public static final int Ed448ph = 1;
    }

    private static class F extends X448Field {
        private F() {
        }
    }

    /* access modifiers changed from: private */
    public static class PointExt {
        int[] x;
        int[] y;
        int[] z;

        private PointExt() {
            this.x = F.create();
            this.y = F.create();
            this.z = F.create();
        }
    }

    /* access modifiers changed from: private */
    public static class PointPrecomp {
        int[] x;
        int[] y;

        private PointPrecomp() {
            this.x = F.create();
            this.y = F.create();
        }
    }

    private static byte[] calculateS(byte[] r, byte[] k, byte[] s) {
        int[] t = new int[28];
        decodeScalar(r, 0, t);
        int[] u = new int[14];
        decodeScalar(k, 0, u);
        int[] v = new int[14];
        decodeScalar(s, 0, v);
        Nat.mulAddTo(14, u, v, t);
        byte[] result = new byte[114];
        for (int i = 0; i < t.length; i++) {
            encode32(t[i], result, i * 4);
        }
        return reduceScalar(result);
    }

    private static boolean checkContextVar(byte[] ctx) {
        return ctx != null && ctx.length < 256;
    }

    private static int checkPoint(int[] x, int[] y) {
        int[] t = F.create();
        int[] u = F.create();
        int[] v = F.create();
        F.sqr(x, u);
        F.sqr(y, v);
        F.mul(u, v, t);
        F.add(u, v, u);
        F.mul(t, 39081, t);
        F.subOne(t);
        F.add(t, u, t);
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
        F.add(u, v, u);
        F.mul(u, w, u);
        F.sqr(w, w);
        F.mul(t, 39081, t);
        F.sub(t, w, t);
        F.add(t, u, t);
        F.normalize(t);
        return F.isZero(t);
    }

    private static boolean checkPointVar(byte[] p) {
        if ((p[56] & Byte.MAX_VALUE) != 0) {
            return false;
        }
        int[] t = new int[14];
        decode32(p, 0, t, 0, 14);
        if (!Nat.gte(14, t, P)) {
            return true;
        }
        return false;
    }

    private static boolean checkScalarVar(byte[] s, int[] n) {
        if (s[56] != 0) {
            return false;
        }
        decodeScalar(s, 0, n);
        if (!Nat.gte(14, n, L)) {
            return true;
        }
        return false;
    }

    private static byte[] copy(byte[] buf, int off, int len) {
        byte[] result = new byte[len];
        System.arraycopy(buf, off, result, 0, len);
        return result;
    }

    public static Xof createPrehash() {
        return createXof();
    }

    private static Xof createXof() {
        return new SHAKEDigest(256);
    }

    private static int decode16(byte[] bs, int off) {
        return (bs[off] & 255) | ((bs[off + 1] & 255) << 8);
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

    private static boolean decodePointVar(byte[] p, int pOff, boolean negate, PointExt r) {
        boolean z = false;
        byte[] py = copy(p, pOff, 57);
        if (!checkPointVar(py)) {
            return false;
        }
        int x_0 = (py[56] & 128) >>> 7;
        py[56] = (byte) (py[56] & Byte.MAX_VALUE);
        F.decode(py, 0, r.y);
        int[] u = F.create();
        int[] v = F.create();
        F.sqr(r.y, u);
        F.mul(u, 39081, v);
        F.negate(u, u);
        F.addOne(u);
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
        pointExtendXY(r);
        return true;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n) {
        decode32(k, kOff, n, 0, 14);
    }

    private static void dom4(Xof d, byte phflag, byte[] ctx) {
        int n = DOM4_PREFIX.length;
        byte[] t = new byte[(n + 2 + ctx.length)];
        System.arraycopy(DOM4_PREFIX, 0, t, 0, n);
        t[n] = phflag;
        t[n + 1] = (byte) ctx.length;
        System.arraycopy(ctx, 0, t, n + 2, ctx.length);
        d.update(t, 0, t.length);
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

    private static int encodePoint(PointExt p, byte[] r, int rOff) {
        int[] x = F.create();
        int[] y = F.create();
        F.inv(p.z, y);
        F.mul(p.x, y, x);
        F.mul(p.y, y, y);
        F.normalize(x);
        F.normalize(y);
        int result = checkPoint(x, y);
        F.encode(y, r, rOff);
        r[(rOff + 57) - 1] = (byte) ((x[0] & 1) << 7);
        return result;
    }

    public static void generatePrivateKey(SecureRandom random, byte[] k) {
        random.nextBytes(k);
    }

    public static void generatePublicKey(byte[] sk, int skOff, byte[] pk, int pkOff) {
        Xof d = createXof();
        byte[] h = new byte[114];
        d.update(sk, skOff, 57);
        d.doFinal(h, 0, h.length);
        byte[] s = new byte[57];
        pruneScalar(h, 0, s);
        scalarMultBaseEncoded(s, pk, pkOff);
    }

    private static int getWindow4(int[] x, int n) {
        return (x[n >>> 3] >>> ((n & 7) << 2)) & 15;
    }

    private static byte[] getWnafVar(int[] n, int width) {
        int[] t = new int[28];
        int tPos = t.length;
        int c = 0;
        int i = 14;
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
        byte[] ws = new byte[447];
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

    private static void implSign(Xof d, byte[] h, byte[] s, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        dom4(d, phflag, ctx);
        d.update(h, 57, 57);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);
        byte[] r = reduceScalar(h);
        byte[] R = new byte[57];
        scalarMultBaseEncoded(r, R, 0);
        dom4(d, phflag, ctx);
        d.update(R, 0, 57);
        d.update(pk, pkOff, 57);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);
        byte[] S = calculateS(r, reduceScalar(h), s);
        System.arraycopy(R, 0, sig, sigOff, 57);
        System.arraycopy(S, 0, sig, sigOff + 57, 57);
    }

    private static void implSign(byte[] sk, int skOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        if (!checkContextVar(ctx)) {
            throw new IllegalArgumentException("ctx");
        }
        Xof d = createXof();
        byte[] h = new byte[114];
        d.update(sk, skOff, 57);
        d.doFinal(h, 0, h.length);
        byte[] s = new byte[57];
        pruneScalar(h, 0, s);
        byte[] pk = new byte[57];
        scalarMultBaseEncoded(s, pk, 0);
        implSign(d, h, s, pk, 0, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    private static void implSign(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen, byte[] sig, int sigOff) {
        if (!checkContextVar(ctx)) {
            throw new IllegalArgumentException("ctx");
        }
        Xof d = createXof();
        byte[] h = new byte[114];
        d.update(sk, skOff, 57);
        d.doFinal(h, 0, h.length);
        byte[] s = new byte[57];
        pruneScalar(h, 0, s);
        implSign(d, h, s, pk, pkOff, ctx, phflag, m, mOff, mLen, sig, sigOff);
    }

    private static boolean implVerify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte phflag, byte[] m, int mOff, int mLen) {
        if (!checkContextVar(ctx)) {
            throw new IllegalArgumentException("ctx");
        }
        byte[] R = copy(sig, sigOff, 57);
        byte[] S = copy(sig, sigOff + 57, 57);
        if (!checkPointVar(R)) {
            return false;
        }
        int[] nS = new int[14];
        if (!checkScalarVar(S, nS)) {
            return false;
        }
        PointExt pA = new PointExt();
        if (!decodePointVar(pk, pkOff, true, pA)) {
            return false;
        }
        Xof d = createXof();
        byte[] h = new byte[114];
        dom4(d, phflag, ctx);
        d.update(R, 0, 57);
        d.update(pk, pkOff, 57);
        d.update(m, mOff, mLen);
        d.doFinal(h, 0, h.length);
        int[] nA = new int[14];
        decodeScalar(reduceScalar(h), 0, nA);
        PointExt pR = new PointExt();
        scalarMultStrausVar(nS, nA, pA, pR);
        byte[] check = new byte[57];
        return encodePoint(pR, check, 0) != 0 && Arrays.areEqual(check, R);
    }

    private static boolean isNeutralElementVar(int[] x, int[] y, int[] z) {
        return F.isZeroVar(x) && F.areEqualVar(y, z);
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
        F.mul(p.z, r.z, a);
        F.sqr(a, b);
        F.mul(p.x, r.x, c);
        F.mul(p.y, r.y, d);
        F.mul(c, d, e);
        F.mul(e, 39081, e);
        F.add(b, e, f);
        F.sub(b, e, g);
        F.add(p.x, p.y, b);
        F.add(r.x, r.y, e);
        F.mul(b, e, h);
        F.add(d, c, b);
        F.sub(d, c, e);
        F.carry(b);
        F.sub(h, b, h);
        F.mul(h, a, h);
        F.mul(e, a, e);
        F.mul(f, h, r.x);
        F.mul(e, g, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointAddVar(boolean negate, PointExt p, PointExt r) {
        int[] nb;
        int[] ne;
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
            nb = e;
            ne = b;
            nf = g;
            ng = f;
            F.sub(p.y, p.x, h);
        } else {
            nb = b;
            ne = e;
            nf = f;
            ng = g;
            F.add(p.y, p.x, h);
        }
        F.mul(p.z, r.z, a);
        F.sqr(a, b);
        F.mul(p.x, r.x, c);
        F.mul(p.y, r.y, d);
        F.mul(c, d, e);
        F.mul(e, 39081, e);
        F.add(b, e, nf);
        F.sub(b, e, ng);
        F.add(r.x, r.y, e);
        F.mul(h, e, h);
        F.add(d, c, nb);
        F.sub(d, c, ne);
        F.carry(nb);
        F.sub(h, b, h);
        F.mul(h, a, h);
        F.mul(e, a, e);
        F.mul(f, h, r.x);
        F.mul(e, g, r.y);
        F.mul(f, g, r.z);
    }

    private static void pointAddPrecomp(PointPrecomp p, PointExt r) {
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = F.create();
        int[] f = F.create();
        int[] g = F.create();
        int[] h = F.create();
        F.sqr(r.z, b);
        F.mul(p.x, r.x, c);
        F.mul(p.y, r.y, d);
        F.mul(c, d, e);
        F.mul(e, 39081, e);
        F.add(b, e, f);
        F.sub(b, e, g);
        F.add(p.x, p.y, b);
        F.add(r.x, r.y, e);
        F.mul(b, e, h);
        F.add(d, c, b);
        F.sub(d, c, e);
        F.carry(b);
        F.sub(h, b, h);
        F.mul(h, r.z, h);
        F.mul(e, r.z, e);
        F.mul(f, h, r.x);
        F.mul(e, g, r.y);
        F.mul(f, g, r.z);
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
    }

    private static void pointDouble(PointExt r) {
        int[] b = F.create();
        int[] c = F.create();
        int[] d = F.create();
        int[] e = F.create();
        int[] h = F.create();
        int[] j = F.create();
        F.add(r.x, r.y, b);
        F.sqr(b, b);
        F.sqr(r.x, c);
        F.sqr(r.y, d);
        F.add(c, d, e);
        F.carry(e);
        F.sqr(r.z, h);
        F.add(h, h, h);
        F.carry(h);
        F.sub(e, h, j);
        F.sub(b, e, b);
        F.sub(c, d, c);
        F.mul(b, j, r.x);
        F.mul(e, c, r.y);
        F.mul(e, j, r.z);
    }

    private static void pointExtendXY(PointExt p) {
        F.one(p.z);
    }

    private static void pointLookup(int block, int index, PointPrecomp p) {
        int off = block * 16 * 2 * 16;
        for (int i = 0; i < 16; i++) {
            int cond = ((i ^ index) - 1) >> 31;
            F.cmov(cond, precompBase, off, p.x, 0);
            int off2 = off + 16;
            F.cmov(cond, precompBase, off2, p.y, 0);
            off = off2 + 16;
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
            int off2 = off + 16;
            F.cmov(cond, table, off2, r.y, 0);
            int off3 = off2 + 16;
            F.cmov(cond, table, off3, r.z, 0);
            off = off3 + 16;
        }
        F.cnegate(sign, r.x);
    }

    private static void pointLookup15(int[] table, PointExt r) {
        F.copy(table, 336, r.x, 0);
        int off = 336 + 16;
        F.copy(table, off, r.y, 0);
        F.copy(table, off + 16, r.z, 0);
    }

    private static int[] pointPrecompute(PointExt p, int count) {
        PointExt q = pointCopy(p);
        PointExt d = pointCopy(q);
        pointDouble(d);
        int[] table = F.createTable(count * 3);
        int off = 0;
        int i = 0;
        while (true) {
            F.copy(q.x, 0, table, off);
            int off2 = off + 16;
            F.copy(q.y, 0, table, off2);
            int off3 = off2 + 16;
            F.copy(q.z, 0, table, off3);
            off = off3 + 16;
            i++;
            if (i == count) {
                return table;
            }
            pointAdd(d, q);
        }
    }

    private static PointExt[] pointPrecomputeVar(PointExt p, int count) {
        PointExt d = pointCopy(p);
        pointDouble(d);
        PointExt[] table = new PointExt[count];
        table[0] = pointCopy(p);
        for (int i = 1; i < count; i++) {
            table[i] = pointCopy(table[i - 1]);
            pointAddVar(false, d, table[i]);
        }
        return table;
    }

    private static void pointSetNeutral(PointExt p) {
        F.zero(p.x);
        F.one(p.y);
        F.one(p.z);
    }

    /* JADX INFO: Multiple debug info for r19v4 int[]: [D('t' int), D('t' int[])] */
    public static void precompute() {
        synchronized (precompLock) {
            if (precompBase == null) {
                PointExt p = new PointExt();
                F.copy(B_x, 0, p.x, 0);
                F.copy(B_y, 0, p.y, 0);
                pointExtendXY(p);
                precompBaseTable = pointPrecomputeVar(p, 32);
                precompBase = F.createTable(160);
                int off = 0;
                for (int b = 0; b < 5; b++) {
                    PointExt[] ds = new PointExt[5];
                    PointExt sum = new PointExt();
                    pointSetNeutral(sum);
                    for (int t = 0; t < 5; t++) {
                        pointAddVar(true, p, sum);
                        pointDouble(p);
                        ds[t] = pointCopy(p);
                        if (b + t != 8) {
                            for (int s = 1; s < 18; s++) {
                                pointDouble(p);
                            }
                        }
                    }
                    PointExt[] points = new PointExt[16];
                    points[0] = sum;
                    int k = 0 + 1;
                    for (int t2 = 0; t2 < 4; t2++) {
                        int size = 1 << t2;
                        int j = 0;
                        while (j < size) {
                            points[k] = pointCopy(points[k - size]);
                            pointAddVar(false, ds[t2], points[k]);
                            j++;
                            k++;
                        }
                    }
                    int[] cs = F.createTable(16);
                    int[] u = F.create();
                    F.copy(points[0].z, 0, u, 0);
                    F.copy(u, 0, cs, 0);
                    int i = 0;
                    while (true) {
                        i++;
                        if (i >= 16) {
                            break;
                        }
                        F.mul(u, points[i].z, u);
                        F.copy(u, 0, cs, i * 16);
                    }
                    F.invVar(u, u);
                    int[] t3 = F.create();
                    int i2 = i - 1;
                    while (i2 > 0) {
                        int i3 = i2 - 1;
                        F.copy(cs, i3 * 16, t3, 0);
                        F.mul(t3, u, t3);
                        F.copy(t3, 0, cs, i2 * 16);
                        F.mul(u, points[i2].z, u);
                        i2 = i3;
                    }
                    F.copy(u, 0, cs, 0);
                    for (int i4 = 0; i4 < 16; i4++) {
                        PointExt q = points[i4];
                        F.copy(cs, i4 * 16, q.z, 0);
                        F.mul(q.x, q.z, q.x);
                        F.mul(q.y, q.z, q.y);
                        F.copy(q.x, 0, precompBase, off);
                        int off2 = off + 16;
                        F.copy(q.y, 0, precompBase, off2);
                        off = off2 + 16;
                    }
                }
            }
        }
    }

    private static void pruneScalar(byte[] n, int nOff, byte[] r) {
        System.arraycopy(n, nOff, r, 0, 56);
        r[0] = (byte) (r[0] & 252);
        r[55] = (byte) (r[55] | 128);
        r[56] = 0;
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
        long x18 = ((long) decode32(n, 63)) & M32L;
        long x19 = ((long) (decode24(n, 67) << 4)) & M32L;
        long x20 = ((long) decode32(n, 70)) & M32L;
        long x21 = ((long) (decode24(n, 74) << 4)) & M32L;
        long x22 = ((long) decode32(n, 77)) & M32L;
        long x23 = ((long) (decode24(n, 81) << 4)) & M32L;
        long x24 = ((long) decode32(n, 84)) & M32L;
        long x25 = ((long) (decode24(n, 88) << 4)) & M32L;
        long x26 = ((long) decode32(n, 91)) & M32L;
        long x27 = ((long) (decode24(n, 95) << 4)) & M32L;
        long x28 = ((long) decode32(n, 98)) & M32L;
        long x29 = ((long) (decode24(n, 102) << 4)) & M32L;
        long x30 = ((long) decode32(n, 105)) & M32L;
        long x31 = ((long) (decode24(n, 109) << 4)) & M32L;
        long x32 = ((long) decode16(n, 112)) & M32L;
        long x312 = x31 + (x30 >>> 28);
        long x302 = x30 & M28L;
        long x292 = x29 + (x28 >>> 28);
        long x282 = x28 & M28L;
        long x202 = x20 + (96434764 * x32) + (227822194 * x312) + (149865618 * x302) + (550336261 * x292);
        long x272 = x27 + (x26 >>> 28);
        long x262 = x26 & M28L;
        long x172 = x17 + (30366549 * x32) + (163752818 * x312) + (258169998 * x302) + (96434764 * x292) + (227822194 * x282) + (149865618 * x272) + (550336261 * x262);
        long x252 = x25 + (x24 >>> 28);
        long x242 = x24 & M28L;
        long x212 = x21 + (227822194 * x32) + (149865618 * x312) + (550336261 * x302) + (x202 >>> 28);
        long x203 = x202 & M28L;
        long x222 = x22 + (149865618 * x32) + (550336261 * x312) + (x212 >>> 28);
        long x213 = x212 & M28L;
        long x232 = x23 + (550336261 * x32) + (x222 >>> 28);
        long x223 = x222 & M28L;
        long x243 = x242 + (x232 >>> 28);
        long x233 = x232 & M28L;
        long x142 = x14 + (43969588 * x302) + (30366549 * x292) + (163752818 * x282) + (258169998 * x272) + (96434764 * x262) + (227822194 * x252) + (149865618 * x243) + (550336261 * x233);
        long x182 = x18 + (163752818 * x32) + (258169998 * x312) + (96434764 * x302) + (227822194 * x292) + (149865618 * x282) + (550336261 * x272) + (x172 >>> 28);
        long x173 = x172 & M28L;
        long x192 = x19 + (258169998 * x32) + (96434764 * x312) + (227822194 * x302) + (149865618 * x292) + (550336261 * x282) + (x182 >>> 28);
        long x183 = x182 & M28L;
        long x204 = x203 + (x192 >>> 28);
        long x193 = x192 & M28L;
        long x214 = x213 + (x204 >>> 28);
        long x205 = x204 & M28L;
        long x152 = x15 + (43969588 * x312) + (30366549 * x302) + (163752818 * x292) + (258169998 * x282) + (96434764 * x272) + (227822194 * x262) + (149865618 * x252) + (550336261 * x243) + (x142 >>> 28);
        long x143 = x142 & M28L;
        long x162 = x16 + (43969588 * x32) + (30366549 * x312) + (163752818 * x302) + (258169998 * x292) + (96434764 * x282) + (227822194 * x272) + (149865618 * x262) + (550336261 * x252) + (x152 >>> 28);
        long x153 = x152 & M28L;
        long x174 = x173 + (x162 >>> 28);
        long x163 = x162 & M28L;
        long x184 = x183 + (x174 >>> 28);
        long x175 = x174 & M28L;
        long x154 = x153 & M26L;
        long x164 = (x163 * 4) + (x153 >>> 26) + 1;
        long x002 = x00 + (78101261 * x164);
        long x012 = x01 + (43969588 * x175) + (141809365 * x164) + (x002 >>> 28);
        long x003 = x002 & M28L;
        long x022 = x02 + (43969588 * x184) + (30366549 * x175) + (175155932 * x164) + (x012 >>> 28);
        long x013 = x012 & M28L;
        long x032 = x03 + (43969588 * x193) + (30366549 * x184) + (163752818 * x175) + (64542499 * x164) + (x022 >>> 28);
        long x023 = x022 & M28L;
        long x042 = x04 + (43969588 * x205) + (30366549 * x193) + (163752818 * x184) + (258169998 * x175) + (158326419 * x164) + (x032 >>> 28);
        long x033 = x032 & M28L;
        long x052 = x05 + (43969588 * x214) + (30366549 * x205) + (163752818 * x193) + (258169998 * x184) + (96434764 * x175) + (191173276 * x164) + (x042 >>> 28);
        long x043 = x042 & M28L;
        long x062 = x06 + (43969588 * x223) + (30366549 * x214) + (163752818 * x205) + (258169998 * x193) + (96434764 * x184) + (227822194 * x175) + (104575268 * x164) + (x052 >>> 28);
        long x053 = x052 & M28L;
        long x072 = x07 + (43969588 * x233) + (30366549 * x223) + (163752818 * x214) + (258169998 * x205) + (96434764 * x193) + (227822194 * x184) + (149865618 * x175) + (137584065 * x164) + (x062 >>> 28);
        long x063 = x062 & M28L;
        long x082 = x08 + (43969588 * x243) + (30366549 * x233) + (163752818 * x223) + (258169998 * x214) + (96434764 * x205) + (227822194 * x193) + (149865618 * x184) + (550336261 * x175) + (x072 >>> 28);
        long x073 = x072 & M28L;
        long x092 = x09 + (43969588 * x252) + (30366549 * x243) + (163752818 * x233) + (258169998 * x223) + (96434764 * x214) + (227822194 * x205) + (149865618 * x193) + (550336261 * x184) + (x082 >>> 28);
        long x083 = x082 & M28L;
        long x102 = x10 + (43969588 * x262) + (30366549 * x252) + (163752818 * x243) + (258169998 * x233) + (96434764 * x223) + (227822194 * x214) + (149865618 * x205) + (550336261 * x193) + (x092 >>> 28);
        long x093 = x092 & M28L;
        long x112 = x11 + (43969588 * x272) + (30366549 * x262) + (163752818 * x252) + (258169998 * x243) + (96434764 * x233) + (227822194 * x223) + (149865618 * x214) + (550336261 * x205) + (x102 >>> 28);
        long x103 = x102 & M28L;
        long x122 = x12 + (43969588 * x282) + (30366549 * x272) + (163752818 * x262) + (258169998 * x252) + (96434764 * x243) + (227822194 * x233) + (149865618 * x223) + (550336261 * x214) + (x112 >>> 28);
        long x113 = x112 & M28L;
        long x132 = x13 + (43969588 * x292) + (30366549 * x282) + (163752818 * x272) + (258169998 * x262) + (96434764 * x252) + (227822194 * x243) + (149865618 * x233) + (550336261 * x223) + (x122 >>> 28);
        long x123 = x122 & M28L;
        long x144 = x143 + (x132 >>> 28);
        long x133 = x132 & M28L;
        long x155 = x154 + (x144 >>> 28);
        long x145 = x144 & M28L;
        long x165 = x155 >>> 26;
        long x156 = x155 & M26L;
        long x166 = x165 - 1;
        long x004 = x003 - (78101261 & x166);
        long x014 = (x013 - (141809365 & x166)) + (x004 >> 28);
        long x005 = x004 & M28L;
        long x024 = (x023 - (175155932 & x166)) + (x014 >> 28);
        long x015 = x014 & M28L;
        long x034 = (x033 - (64542499 & x166)) + (x024 >> 28);
        long x025 = x024 & M28L;
        long x044 = (x043 - (158326419 & x166)) + (x034 >> 28);
        long x035 = x034 & M28L;
        long x054 = (x053 - (191173276 & x166)) + (x044 >> 28);
        long x045 = x044 & M28L;
        long x064 = (x063 - (104575268 & x166)) + (x054 >> 28);
        long x055 = x054 & M28L;
        long x074 = (x073 - (137584065 & x166)) + (x064 >> 28);
        long x065 = x064 & M28L;
        long x084 = x083 + (x074 >> 28);
        long x075 = x074 & M28L;
        long x094 = x093 + (x084 >> 28);
        long x085 = x084 & M28L;
        long x104 = x103 + (x094 >> 28);
        long x095 = x094 & M28L;
        long x114 = x113 + (x104 >> 28);
        long x105 = x104 & M28L;
        long x124 = x123 + (x114 >> 28);
        long x115 = x114 & M28L;
        long x134 = x133 + (x124 >> 28);
        long x125 = x124 & M28L;
        long x146 = x145 + (x134 >> 28);
        long x135 = x134 & M28L;
        long x157 = x156 + (x146 >> 28);
        long x147 = x146 & M28L;
        byte[] r = new byte[57];
        encode56((x015 << 28) | x005, r, 0);
        encode56((x035 << 28) | x025, r, 7);
        encode56((x055 << 28) | x045, r, 14);
        encode56((x075 << 28) | x065, r, 21);
        encode56((x095 << 28) | x085, r, 28);
        encode56((x115 << 28) | x105, r, 35);
        encode56((x135 << 28) | x125, r, 42);
        encode56((x157 << 28) | x147, r, 49);
        return r;
    }

    private static void scalarMult(byte[] k, PointExt p, PointExt r) {
        int[] n = new int[14];
        decodeScalar(k, 0, n);
        Nat.shiftDownBit(14, n, Nat.cadd(14, (n[0] ^ -1) & 1, n, L, n));
        int[] table = pointPrecompute(p, 8);
        PointExt q = new PointExt();
        pointLookup15(table, r);
        pointAdd(p, r);
        int w = 111;
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

    private static void scalarMultBase(byte[] k, PointExt r) {
        precompute();
        int[] n = new int[15];
        decodeScalar(k, 0, n);
        n[14] = Nat.cadd(14, (n[0] ^ -1) & 1, n, L, n) + 4;
        Nat.shiftDownBit(n.length, n, 0);
        PointPrecomp p = new PointPrecomp();
        pointSetNeutral(r);
        int cOff = 17;
        while (true) {
            int tPos = cOff;
            for (int b = 0; b < 5; b++) {
                int w = 0;
                for (int t = 0; t < 5; t++) {
                    w = (w & ((1 << t) ^ -1)) ^ ((n[tPos >>> 5] >>> (tPos & 31)) << t);
                    tPos += 18;
                }
                int sign = (w >>> 4) & 1;
                pointLookup(b, ((-sign) ^ w) & 15, p);
                F.cnegate(sign, p.x);
                pointAddPrecomp(p, r);
            }
            cOff--;
            if (cOff >= 0) {
                pointDouble(r);
            } else {
                return;
            }
        }
    }

    private static void scalarMultBaseEncoded(byte[] k, byte[] r, int rOff) {
        PointExt p = new PointExt();
        scalarMultBase(k, p);
        if (encodePoint(p, r, rOff) == 0) {
            throw new IllegalStateException();
        }
    }

    public static void scalarMultBaseXY(X448.Friend friend, byte[] k, int kOff, int[] x, int[] y) {
        if (friend == null) {
            throw new NullPointerException("This method is only for use by X448");
        }
        byte[] n = new byte[57];
        pruneScalar(k, kOff, n);
        PointExt p = new PointExt();
        scalarMultBase(n, p);
        if (checkPoint(p.x, p.y, p.z) == 0) {
            throw new IllegalStateException();
        }
        F.copy(p.x, 0, x, 0);
        F.copy(p.y, 0, y, 0);
    }

    private static void scalarMultOrderVar(PointExt p, PointExt r) {
        byte[] ws_p = getWnafVar(L, 5);
        PointExt[] tp = pointPrecomputeVar(p, 8);
        pointSetNeutral(r);
        int bit = 446;
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

    private static void scalarMultStrausVar(int[] nb, int[] np, PointExt p, PointExt r) {
        precompute();
        byte[] ws_b = getWnafVar(nb, 7);
        byte[] ws_p = getWnafVar(np, 5);
        PointExt[] tp = pointPrecomputeVar(p, 8);
        pointSetNeutral(r);
        int bit = 446;
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

    public static void signPrehash(byte[] sk, int skOff, byte[] ctx, Xof ph, byte[] sig, int sigOff) {
        byte[] m = new byte[64];
        if (64 != ph.doFinal(m, 0, 64)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(sk, skOff, ctx, (byte) 1, m, 0, m.length, sig, sigOff);
    }

    public static void signPrehash(byte[] sk, int skOff, byte[] pk, int pkOff, byte[] ctx, Xof ph, byte[] sig, int sigOff) {
        byte[] m = new byte[64];
        if (64 != ph.doFinal(m, 0, 64)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(sk, skOff, pk, pkOff, ctx, (byte) 1, m, 0, m.length, sig, sigOff);
    }

    public static boolean validatePublicKeyFull(byte[] pk, int pkOff) {
        PointExt p = new PointExt();
        if (!decodePointVar(pk, pkOff, false, p)) {
            return false;
        }
        F.normalize(p.x);
        F.normalize(p.y);
        F.normalize(p.z);
        if (isNeutralElementVar(p.x, p.y, p.z)) {
            return false;
        }
        PointExt r = new PointExt();
        scalarMultOrderVar(p, r);
        F.normalize(r.x);
        F.normalize(r.y);
        F.normalize(r.z);
        return isNeutralElementVar(r.x, r.y, r.z);
    }

    public static boolean validatePublicKeyPartial(byte[] pk, int pkOff) {
        return decodePointVar(pk, pkOff, false, new PointExt());
    }

    public static boolean verify(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] m, int mOff, int mLen) {
        return implVerify(sig, sigOff, pk, pkOff, ctx, (byte) 0, m, mOff, mLen);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, byte[] ph, int phOff) {
        return implVerify(sig, sigOff, pk, pkOff, ctx, (byte) 1, ph, phOff, 64);
    }

    public static boolean verifyPrehash(byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] ctx, Xof ph) {
        byte[] m = new byte[64];
        if (64 == ph.doFinal(m, 0, 64)) {
            return implVerify(sig, sigOff, pk, pkOff, ctx, (byte) 1, m, 0, m.length);
        }
        throw new IllegalArgumentException("ph");
    }
}
