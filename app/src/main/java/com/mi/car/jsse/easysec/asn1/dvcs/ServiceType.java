package com.mi.car.jsse.easysec.asn1.dvcs;

import com.mi.car.jsse.easysec.asn1.ASN1Enumerated;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import java.math.BigInteger;

public class ServiceType extends ASN1Object {
    public static final ServiceType CCPD = new ServiceType(4);
    public static final ServiceType CPD = new ServiceType(1);
    public static final ServiceType VPKC = new ServiceType(3);
    public static final ServiceType VSD = new ServiceType(2);
    private ASN1Enumerated value;

    public ServiceType(int value2) {
        this.value = new ASN1Enumerated(value2);
    }

    private ServiceType(ASN1Enumerated value2) {
        this.value = value2;
    }

    public static ServiceType getInstance(Object obj) {
        if (obj instanceof ServiceType) {
            return (ServiceType) obj;
        }
        if (obj != null) {
            return new ServiceType(ASN1Enumerated.getInstance(obj));
        }
        return null;
    }

    public static ServiceType getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Enumerated.getInstance(obj, explicit));
    }

    public BigInteger getValue() {
        return this.value.getValue();
    }

    public ASN1Primitive toASN1Primitive() {
        return this.value;
    }

    public String toString() {
        String str;
        int num = this.value.intValueExact();
        StringBuilder append = new StringBuilder().append("").append(num);
        if (num == CPD.value.intValueExact()) {
            str = "(CPD)";
        } else if (num == VSD.value.intValueExact()) {
            str = "(VSD)";
        } else if (num == VPKC.value.intValueExact()) {
            str = "(VPKC)";
        } else {
            str = num == CCPD.value.intValueExact() ? "(CCPD)" : "?";
        }
        return append.append(str).toString();
    }
}
