//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import java.math.BigInteger;

public class PKIStatus extends ASN1Object {
    public static final int GRANTED = 0;
    public static final int GRANTED_WITH_MODS = 1;
    public static final int REJECTION = 2;
    public static final int WAITING = 3;
    public static final int REVOCATION_WARNING = 4;
    public static final int REVOCATION_NOTIFICATION = 5;
    public static final int KEY_UPDATE_WARNING = 6;
    public static final PKIStatus granted = new PKIStatus(0);
    public static final PKIStatus grantedWithMods = new PKIStatus(1);
    public static final PKIStatus rejection = new PKIStatus(2);
    public static final PKIStatus waiting = new PKIStatus(3);
    public static final PKIStatus revocationWarning = new PKIStatus(4);
    public static final PKIStatus revocationNotification = new PKIStatus(5);
    public static final PKIStatus keyUpdateWaiting = new PKIStatus(6);
    private final ASN1Integer value;

    private PKIStatus(int value) {
        this(new ASN1Integer((long)value));
    }

    private PKIStatus(ASN1Integer value) {
        this.value = value;
    }

    public static PKIStatus getInstance(Object o) {
        if (o instanceof PKIStatus) {
            return (PKIStatus)o;
        } else {
            return o != null ? new PKIStatus(ASN1Integer.getInstance(o)) : null;
        }
    }

    public BigInteger getValue() {
        return this.value.getValue();
    }

    public ASN1Primitive toASN1Primitive() {
        return this.value;
    }
}
