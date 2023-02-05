package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import java.util.HashMap;
import java.util.Map;

public class LMOtsParameters {
    public static final int reserved = 0;
    public static final LMOtsParameters sha256_n32_w1 = new LMOtsParameters(1, 32, 1, 265, 7, 8516, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w2 = new LMOtsParameters(2, 32, 2, 133, 6, 4292, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w4 = new LMOtsParameters(3, 32, 4, 67, 4, 2180, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w8 = new LMOtsParameters(4, 32, 8, 34, 0, 1124, NISTObjectIdentifiers.id_sha256);
    private static final Map<Object, LMOtsParameters> suppliers = new HashMap<Object, LMOtsParameters>() {
        /* class com.mi.car.jsse.easysec.pqc.crypto.lms.LMOtsParameters.AnonymousClass1 */

        {
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w1.type), LMOtsParameters.sha256_n32_w1);
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w2.type), LMOtsParameters.sha256_n32_w2);
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w4.type), LMOtsParameters.sha256_n32_w4);
            put(Integer.valueOf(LMOtsParameters.sha256_n32_w8.type), LMOtsParameters.sha256_n32_w8);
        }
    };
    private final ASN1ObjectIdentifier digestOID;
    private final int ls;
    private final int n;
    private final int p;
    private final int sigLen;
    private final int type;
    private final int w;

    protected LMOtsParameters(int type2, int n2, int w2, int p2, int ls2, int sigLen2, ASN1ObjectIdentifier digestOID2) {
        this.type = type2;
        this.n = n2;
        this.w = w2;
        this.p = p2;
        this.ls = ls2;
        this.sigLen = sigLen2;
        this.digestOID = digestOID2;
    }

    public int getType() {
        return this.type;
    }

    public int getN() {
        return this.n;
    }

    public int getW() {
        return this.w;
    }

    public int getP() {
        return this.p;
    }

    public int getLs() {
        return this.ls;
    }

    public int getSigLen() {
        return this.sigLen;
    }

    public ASN1ObjectIdentifier getDigestOID() {
        return this.digestOID;
    }

    public static LMOtsParameters getParametersForType(int type2) {
        return suppliers.get(Integer.valueOf(type2));
    }
}
