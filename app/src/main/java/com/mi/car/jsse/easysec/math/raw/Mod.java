package com.mi.car.jsse.easysec.math.raw;

import com.mi.car.jsse.easysec.util.Integers;
import java.util.Random;

public abstract class Mod {
    private static final int M30 = 1073741823;
    private static final long M32L = 4294967295L;

    public static void checkedModOddInverse(int[] m, int[] x, int[] z) {
        if (modOddInverse(m, x, z) == 0) {
            throw new ArithmeticException("Inverse does not exist.");
        }
    }

    public static void checkedModOddInverseVar(int[] m, int[] x, int[] z) {
        if (!modOddInverseVar(m, x, z)) {
            throw new ArithmeticException("Inverse does not exist.");
        }
    }

    public static int inverse32(int d) {
        int x = d * (2 - (d * d));
        int x2 = x * (2 - (d * x));
        int x3 = x2 * (2 - (d * x2));
        return x3 * (2 - (d * x3));
    }

    public static int modOddInverse(int[] m, int[] x, int[] z) {
        int len32 = m.length;
        int bits = (len32 << 5) - Integers.numberOfLeadingZeros(m[len32 - 1]);
        int len30 = (bits + 29) / 30;
        int[] t = new int[4];
        int[] D = new int[len30];
        int[] E = new int[len30];
        int[] F = new int[len30];
        int[] G = new int[len30];
        int[] M = new int[len30];
        E[0] = 1;
        encode30(bits, x, 0, G, 0);
        encode30(bits, m, 0, M, 0);
        System.arraycopy(M, 0, F, 0, len30);
        int delta = 0;
        int m0Inv32 = inverse32(M[0]);
        int maxDivsteps = getMaximumDivsteps(bits);
        for (int divSteps = 0; divSteps < maxDivsteps; divSteps += 30) {
            delta = divsteps30(delta, F[0], G[0], t);
            updateDE30(len30, D, E, t, m0Inv32, M);
            updateFG30(len30, F, G, t);
        }
        int signF = F[len30 - 1] >> 31;
        cnegate30(len30, signF, F);
        cnormalize30(len30, signF, D, M);
        decode30(bits, D, 0, z, 0);
        return Nat.equalTo(len30, F, 1) & Nat.equalToZero(len30, G);
    }

    public static boolean modOddInverseVar(int[] m, int[] x, int[] z) {
        int len32 = m.length;
        int bits = (len32 << 5) - Integers.numberOfLeadingZeros(m[len32 - 1]);
        int len30 = (bits + 29) / 30;
        int[] t = new int[4];
        int[] D = new int[len30];
        int[] E = new int[len30];
        int[] F = new int[len30];
        int[] G = new int[len30];
        int[] M = new int[len30];
        E[0] = 1;
        encode30(bits, x, 0, G, 0);
        encode30(bits, m, 0, M, 0);
        System.arraycopy(M, 0, F, 0, len30);
        int eta = -1 - (Integers.numberOfLeadingZeros(G[len30 - 1] | 1) - (((len30 * 30) + 2) - bits));
        int lenFG = len30;
        int m0Inv32 = inverse32(M[0]);
        int maxDivsteps = getMaximumDivsteps(bits);
        int divsteps = 0;
        while (!Nat.isZero(lenFG, G)) {
            if (divsteps >= maxDivsteps) {
                return false;
            }
            divsteps += 30;
            eta = divsteps30Var(eta, F[0], G[0], t);
            updateDE30(len30, D, E, t, m0Inv32, M);
            updateFG30(lenFG, F, G, t);
            int fn = F[lenFG - 1];
            int gn = G[lenFG - 1];
            if ((((lenFG - 2) >> 31) | ((fn >> 31) ^ fn) | ((gn >> 31) ^ gn)) == 0) {
                int i = lenFG - 2;
                F[i] = F[i] | (fn << 30);
                int i2 = lenFG - 2;
                G[i2] = G[i2] | (gn << 30);
                lenFG--;
            }
        }
        int signF = F[lenFG - 1] >> 31;
        int signD = D[len30 - 1] >> 31;
        if (signD < 0) {
            signD = add30(len30, D, M);
        }
        if (signF < 0) {
            signD = negate30(len30, D);
            negate30(lenFG, F);
        }
        if (!Nat.isOne(lenFG, F)) {
            return false;
        }
        if (signD < 0) {
            add30(len30, D, M);
        }
        decode30(bits, D, 0, z, 0);
        return true;
    }

    public static int[] random(int[] p) {
        int len = p.length;
        Random rand = new Random();
        int[] s = Nat.create(len);
        int m = p[len - 1];
        int m2 = m | (m >>> 1);
        int m3 = m2 | (m2 >>> 2);
        int m4 = m3 | (m3 >>> 4);
        int m5 = m4 | (m4 >>> 8);
        int m6 = m5 | (m5 >>> 16);
        do {
            for (int i = 0; i != len; i++) {
                s[i] = rand.nextInt();
            }
            int i2 = len - 1;
            s[i2] = s[i2] & m6;
        } while (Nat.gte(len, s, p));
        return s;
    }

    private static int add30(int len30, int[] D, int[] M) {
        int c = 0;
        int last = len30 - 1;
        for (int i = 0; i < last; i++) {
            int c2 = c + D[i] + M[i];
            D[i] = M30 & c2;
            c = c2 >> 30;
        }
        int c3 = c + D[last] + M[last];
        D[last] = c3;
        return c3 >> 30;
    }

    private static void cnegate30(int len30, int cond, int[] D) {
        int c = 0;
        int last = len30 - 1;
        for (int i = 0; i < last; i++) {
            int c2 = c + ((D[i] ^ cond) - cond);
            D[i] = M30 & c2;
            c = c2 >> 30;
        }
        D[last] = c + ((D[last] ^ cond) - cond);
    }

    private static void cnormalize30(int len30, int condNegate, int[] D, int[] M) {
        int last = len30 - 1;
        int c = 0;
        int condAdd = D[last] >> 31;
        for (int i = 0; i < last; i++) {
            int c2 = c + (((D[i] + (M[i] & condAdd)) ^ condNegate) - condNegate);
            D[i] = c2 & M30;
            c = c2 >> 30;
        }
        D[last] = c + (((D[last] + (M[last] & condAdd)) ^ condNegate) - condNegate);
        int c3 = 0;
        int condAdd2 = D[last] >> 31;
        for (int i2 = 0; i2 < last; i2++) {
            int c4 = c3 + D[i2] + (M[i2] & condAdd2);
            D[i2] = c4 & M30;
            c3 = c4 >> 30;
        }
        D[last] = c3 + D[last] + (M[last] & condAdd2);
    }

    private static void decode30(int bits, int[] x, int xOff, int[] z, int zOff) {
        int avail = 0;
        long data = 0;
        int zOff2 = zOff;
        while (bits > 0) {
            while (avail < Math.min(32, bits)) {
                data |= ((long) x[xOff]) << avail;
                avail += 30;
                xOff++;
            }
            z[zOff2] = (int) data;
            data >>>= 32;
            avail -= 32;
            bits -= 32;
            zOff2++;
        }
    }

    private static int divsteps30(int delta, int f0, int g0, int[] t) {
        int u = 1073741824;
        int v = 0;
        int q = 0;
        int r = 1073741824;
        int f = f0;
        int g = g0;
        for (int i = 0; i < 30; i++) {
            int c1 = delta >> 31;
            int c2 = -(g & 1);
            int g2 = g - ((f ^ c1) & c2);
            int q2 = q - ((u ^ c1) & c2);
            int r2 = r - ((v ^ c1) & c2);
            int c22 = c2 & (c1 ^ -1);
            delta = (delta ^ c22) - (c22 - 1);
            f += g2 & c22;
            u += q2 & c22;
            v += r2 & c22;
            g = g2 >> 1;
            q = q2 >> 1;
            r = r2 >> 1;
        }
        t[0] = u;
        t[1] = v;
        t[2] = q;
        t[3] = r;
        return delta;
    }

    private static int divsteps30Var(int eta, int f0, int g0, int[] t) {
        int m;
        int i;
        int u = 1;
        int v = 0;
        int q = 0;
        int r = 1;
        int f = f0;
        int g = g0;
        int i2 = 30;
        while (true) {
            int zeros = Integers.numberOfTrailingZeros((-1 << i2) | g);
            int g2 = g >> zeros;
            u <<= zeros;
            v <<= zeros;
            eta -= zeros;
            i2 -= zeros;
            if (i2 <= 0) {
                t[0] = u;
                t[1] = v;
                t[2] = q;
                t[3] = r;
                return eta;
            }
            if (eta < 0) {
                eta = -eta;
                f = g2;
                g2 = -f;
                u = q;
                q = -u;
                v = r;
                r = -v;
                m = (-1 >>> (32 - (eta + 1 > i2 ? i2 : eta + 1))) & 63;
                i = f * g2 * ((f * f) - 2);
            } else {
                m = (-1 >>> (32 - (eta + 1 > i2 ? i2 : eta + 1))) & 15;
                i = (-(f + (((f + 1) & 4) << 1))) * g2;
            }
            int w = i & m;
            g = g2 + (f * w);
            q += u * w;
            r += v * w;
        }
    }

    private static void encode30(int bits, int[] x, int xOff, int[] z, int zOff) {
        int xOff2;
        int avail = 0;
        long data = 0;
        int zOff2 = zOff;
        int xOff3 = xOff;
        while (bits > 0) {
            if (avail < Math.min(30, bits)) {
                xOff2 = xOff3 + 1;
                data |= (((long) x[xOff3]) & M32L) << avail;
                avail += 32;
            } else {
                xOff2 = xOff3;
            }
            z[zOff2] = ((int) data) & M30;
            data >>>= 30;
            avail -= 30;
            bits -= 30;
            zOff2++;
            xOff3 = xOff2;
        }
    }

    private static int getMaximumDivsteps(int bits) {
        return ((bits < 46 ? 80 : 47) + (bits * 49)) / 17;
    }

    private static int negate30(int len30, int[] D) {
        int c = 0;
        int last = len30 - 1;
        for (int i = 0; i < last; i++) {
            int c2 = c - D[i];
            D[i] = M30 & c2;
            c = c2 >> 30;
        }
        int c3 = c - D[last];
        D[last] = c3;
        return c3 >> 30;
    }

    private static void updateDE30(int len30, int[] D, int[] E, int[] t, int m0Inv32, int[] M) {
        int u = t[0];
        int v = t[1];
        int q = t[2];
        int r = t[3];
        int sd = D[len30 - 1] >> 31;
        int se = E[len30 - 1] >> 31;
        int md = (u & sd) + (v & se);
        int me = (q & sd) + (r & se);
        int mi = M[0];
        int di = D[0];
        int ei = E[0];
        long cd = (((long) u) * ((long) di)) + (((long) v) * ((long) ei));
        long ce = (((long) q) * ((long) di)) + (((long) r) * ((long) ei));
        int md2 = md - (((((int) cd) * m0Inv32) + md) & M30);
        int me2 = me - (((((int) ce) * m0Inv32) + me) & M30);
        long cd2 = (cd + (((long) mi) * ((long) md2))) >> 30;
        long ce2 = (ce + (((long) mi) * ((long) me2))) >> 30;
        for (int i = 1; i < len30; i++) {
            int mi2 = M[i];
            int di2 = D[i];
            int ei2 = E[i];
            long cd3 = cd2 + (((long) u) * ((long) di2)) + (((long) v) * ((long) ei2)) + (((long) mi2) * ((long) md2));
            long ce3 = ce2 + (((long) q) * ((long) di2)) + (((long) r) * ((long) ei2)) + (((long) mi2) * ((long) me2));
            D[i - 1] = ((int) cd3) & M30;
            cd2 = cd3 >> 30;
            E[i - 1] = ((int) ce3) & M30;
            ce2 = ce3 >> 30;
        }
        D[len30 - 1] = (int) cd2;
        E[len30 - 1] = (int) ce2;
    }

    private static void updateFG30(int len30, int[] F, int[] G, int[] t) {
        int u = t[0];
        int v = t[1];
        int q = t[2];
        int r = t[3];
        int fi = F[0];
        int gi = G[0];
        long cf = ((((long) u) * ((long) fi)) + (((long) v) * ((long) gi))) >> 30;
        long cg = ((((long) q) * ((long) fi)) + (((long) r) * ((long) gi))) >> 30;
        for (int i = 1; i < len30; i++) {
            int fi2 = F[i];
            int gi2 = G[i];
            long cf2 = cf + (((long) u) * ((long) fi2)) + (((long) v) * ((long) gi2));
            long cg2 = cg + (((long) q) * ((long) fi2)) + (((long) r) * ((long) gi2));
            F[i - 1] = ((int) cf2) & M30;
            cf = cf2 >> 30;
            G[i - 1] = ((int) cg2) & M30;
            cg = cg2 >> 30;
        }
        F[len30 - 1] = (int) cf;
        G[len30 - 1] = (int) cg;
    }
}
