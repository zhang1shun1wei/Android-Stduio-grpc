package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import java.util.HashMap;
import java.util.Map;

public class LMSigParameters {
    public static final LMSigParameters lms_sha256_n32_h10 = new LMSigParameters(6, 32, 10, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h15 = new LMSigParameters(7, 32, 15, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h20 = new LMSigParameters(8, 32, 20, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h25 = new LMSigParameters(9, 32, 25, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h5 = new LMSigParameters(5, 32, 5, NISTObjectIdentifiers.id_sha256);
    private static Map<Object, LMSigParameters> paramBuilders = new HashMap<Object, LMSigParameters>() {
        /* class com.mi.car.jsse.easysec.pqc.crypto.lms.LMSigParameters.AnonymousClass1 */

        {
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h5.type), LMSigParameters.lms_sha256_n32_h5);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h10.type), LMSigParameters.lms_sha256_n32_h10);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h15.type), LMSigParameters.lms_sha256_n32_h15);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h20.type), LMSigParameters.lms_sha256_n32_h20);
            put(Integer.valueOf(LMSigParameters.lms_sha256_n32_h25.type), LMSigParameters.lms_sha256_n32_h25);
        }
    };
    private final ASN1ObjectIdentifier digestOid;
    private final int h;
    private final int m;
    private final int type;

    protected LMSigParameters(int type2, int m2, int h2, ASN1ObjectIdentifier digestOid2) {
        this.type = type2;
        this.m = m2;
        this.h = h2;
        this.digestOid = digestOid2;
    }

    public int getType() {
        return this.type;
    }

    public int getH() {
        return this.h;
    }

    public int getM() {
        return this.m;
    }

    public ASN1ObjectIdentifier getDigestOID() {
        return this.digestOid;
    }

    static LMSigParameters getParametersForType(int type2) {
        return paramBuilders.get(Integer.valueOf(type2));
    }
}
