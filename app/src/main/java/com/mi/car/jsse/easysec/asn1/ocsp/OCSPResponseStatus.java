package com.mi.car.jsse.easysec.asn1.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1Enumerated;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import java.math.BigInteger;

public class OCSPResponseStatus extends ASN1Object {
    public static final int INTERNAL_ERROR = 2;
    public static final int MALFORMED_REQUEST = 1;
    public static final int SIG_REQUIRED = 5;
    public static final int SUCCESSFUL = 0;
    public static final int TRY_LATER = 3;
    public static final int UNAUTHORIZED = 6;
    private ASN1Enumerated value;

    public OCSPResponseStatus(int value2) {
        this(new ASN1Enumerated(value2));
    }

    private OCSPResponseStatus(ASN1Enumerated value2) {
        this.value = value2;
    }

    public static OCSPResponseStatus getInstance(Object obj) {
        if (obj instanceof OCSPResponseStatus) {
            return (OCSPResponseStatus) obj;
        }
        if (obj != null) {
            return new OCSPResponseStatus(ASN1Enumerated.getInstance(obj));
        }
        return null;
    }

    public int getIntValue() {
        return this.value.intValueExact();
    }

    public BigInteger getValue() {
        return this.value.getValue();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.value;
    }
}
