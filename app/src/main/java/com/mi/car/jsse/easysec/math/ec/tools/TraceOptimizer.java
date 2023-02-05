package com.mi.car.jsse.easysec.math.ec.tools;

import com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParametersHolder;
import com.mi.car.jsse.easysec.crypto.ec.CustomNamedCurves;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.util.Integers;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.SortedSet;
import java.util.TreeSet;

public class TraceOptimizer {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final SecureRandom R = new SecureRandom();

    public static void main(String[] args) {
        SortedSet<String> names = new TreeSet(enumToList(ECNamedCurveTable.getNames()));
        names.addAll(enumToList(CustomNamedCurves.getNames()));
        for (String name : names) {
            X9ECParametersHolder x9 = CustomNamedCurves.getByNameLazy(name);
            if (x9 == null) {
                x9 = ECNamedCurveTable.getByNameLazy(name);
            }
            if (x9 != null) {
                ECCurve curve = x9.getCurve();
                if (ECAlgorithms.isF2mCurve(curve)) {
                    System.out.print(name + ":");
                    implPrintNonZeroTraceBits(curve);
                }
            }
        }
    }

    public static void printNonZeroTraceBits(ECCurve curve) {
        if (!ECAlgorithms.isF2mCurve(curve)) {
            throw new IllegalArgumentException("Trace only defined over characteristic-2 fields");
        }
        implPrintNonZeroTraceBits(curve);
    }

    public static void implPrintNonZeroTraceBits(ECCurve curve) {
        int m = curve.getFieldSize();
        ArrayList nonZeroTraceBits = new ArrayList();
        for (int i = 0; i < m; i++) {
            if ((i & 1) != 0 || i == 0) {
                if (calculateTrace(curve.fromBigInteger(ONE.shiftLeft(i))) != 0) {
                    nonZeroTraceBits.add(Integers.valueOf(i));
                    System.out.print(" " + i);
                }
            } else if (nonZeroTraceBits.contains(Integers.valueOf(i >>> 1))) {
                nonZeroTraceBits.add(Integers.valueOf(i));
                System.out.print(" " + i);
            }
        }
        System.out.println();
        for (int i2 = 0; i2 < 1000; i2++) {
            BigInteger x = new BigInteger(m, R);
            int check = calculateTrace(curve.fromBigInteger(x));
            int tr = 0;
            for (int j = 0; j < nonZeroTraceBits.size(); j++) {
                if (x.testBit(((Integer) nonZeroTraceBits.get(j)).intValue())) {
                    tr ^= 1;
                }
            }
            if (check != tr) {
                throw new IllegalStateException("Optimized-trace sanity check failed");
            }
        }
    }

    private static int calculateTrace(ECFieldElement fe) {
        int m = fe.getFieldSize();
        int k = 31 - Integers.numberOfLeadingZeros(m);
        int mk = 1;
        ECFieldElement tr = fe;
        while (k > 0) {
            tr = tr.squarePow(mk).add(tr);
            k--;
            mk = m >>> k;
            if ((mk & 1) != 0) {
                tr = tr.square().add(fe);
            }
        }
        if (tr.isZero()) {
            return 0;
        }
        if (tr.isOne()) {
            return 1;
        }
        throw new IllegalStateException("Internal error in trace calculation");
    }

    private static ArrayList enumToList(Enumeration en) {
        ArrayList rv = new ArrayList();
        while (en.hasMoreElements()) {
            rv.add(en.nextElement());
        }
        return rv;
    }
}
