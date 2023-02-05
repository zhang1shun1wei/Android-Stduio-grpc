package com.mi.car.jsse.easysec.jce;

import java.util.Enumeration;

public class ECNamedCurveTable {
    /* JADX WARNING: Code restructure failed: missing block: B:5:0x0011, code lost:
        r7 = com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable.getByName(r8);
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static com.mi.car.jsse.easysec.jce.spec.ECNamedCurveParameterSpec getParameterSpec(String r8) {
        /*
            com.mi.car.jsse.easysec.asn1.x9.X9ECParameters r7 = com.mi.car.jsse.easysec.crypto.ec.CustomNamedCurves.getByName(r8)
            if (r7 != 0) goto L_0x0020
            com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier r0 = new com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier     // Catch:{ IllegalArgumentException -> 0x0041 }
            r0.<init>(r8)     // Catch:{ IllegalArgumentException -> 0x0041 }
            com.mi.car.jsse.easysec.asn1.x9.X9ECParameters r7 = com.mi.car.jsse.easysec.crypto.ec.CustomNamedCurves.getByOID(r0)     // Catch:{ IllegalArgumentException -> 0x0041 }
        L_0x000f:
            if (r7 != 0) goto L_0x0020
            com.mi.car.jsse.easysec.asn1.x9.X9ECParameters r7 = com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable.getByName(r8)
            if (r7 != 0) goto L_0x0020
            com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier r0 = new com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier     // Catch:{ IllegalArgumentException -> 0x003f }
            r0.<init>(r8)     // Catch:{ IllegalArgumentException -> 0x003f }
            com.mi.car.jsse.easysec.asn1.x9.X9ECParameters r7 = com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable.getByOID(r0)     // Catch:{ IllegalArgumentException -> 0x003f }
        L_0x0020:
            if (r7 != 0) goto L_0x0024
            r0 = 0
        L_0x0023:
            return r0
        L_0x0024:
            com.mi.car.jsse.easysec.jce.spec.ECNamedCurveParameterSpec r0 = new com.mi.car.jsse.easysec.jce.spec.ECNamedCurveParameterSpec
            com.mi.car.jsse.easysec.math.ec.ECCurve r2 = r7.getCurve()
            com.mi.car.jsse.easysec.math.ec.ECPoint r3 = r7.getG()
            java.math.BigInteger r4 = r7.getN()
            java.math.BigInteger r5 = r7.getH()
            byte[] r6 = r7.getSeed()
            r1 = r8
            r0.<init>(r1, r2, r3, r4, r5, r6)
            goto L_0x0023
        L_0x003f:
            r0 = move-exception
            goto L_0x0020
        L_0x0041:
            r0 = move-exception
            goto L_0x000f
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.jce.ECNamedCurveTable.getParameterSpec(java.lang.String):com.mi.car.jsse.easysec.jce.spec.ECNamedCurveParameterSpec");
    }

    public static Enumeration getNames() {
        return com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable.getNames();
    }
}
