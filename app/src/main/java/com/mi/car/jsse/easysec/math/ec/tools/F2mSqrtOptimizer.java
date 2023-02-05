package com.mi.car.jsse.easysec.math.ec.tools;

import com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParametersHolder;
import com.mi.car.jsse.easysec.crypto.ec.CustomNamedCurves;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.SortedSet;
import java.util.TreeSet;

public class F2mSqrtOptimizer {
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
                    implPrintRootZ(curve);
                }
            }
        }
    }

    public static void printRootZ(ECCurve curve) {
        if (!ECAlgorithms.isF2mCurve(curve)) {
            throw new IllegalArgumentException("Sqrt optimization only defined over characteristic-2 fields");
        }
        implPrintRootZ(curve);
    }

    private static void implPrintRootZ(ECCurve curve) {
        ECFieldElement z = curve.fromBigInteger(BigInteger.valueOf(2));
        ECFieldElement rootZ = z.sqrt();
        System.out.println(rootZ.toBigInteger().toString(16).toUpperCase());
        if (!rootZ.square().equals(z)) {
            throw new IllegalStateException("Optimized-sqrt sanity check failed");
        }
    }

    private static ArrayList enumToList(Enumeration en) {
        ArrayList rv = new ArrayList();
        while (en.hasMoreElements()) {
            rv.add(en.nextElement());
        }
        return rv;
    }
}
