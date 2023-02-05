package com.mi.car.jsse.easysec.asn1.x509.qualified;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;

public class TypeOfBiometricData extends ASN1Object implements ASN1Choice {
    public static final int HANDWRITTEN_SIGNATURE = 1;
    public static final int PICTURE = 0;
    ASN1Encodable obj;

    public static TypeOfBiometricData getInstance(Object obj2) {
        if (obj2 == null || (obj2 instanceof TypeOfBiometricData)) {
            return (TypeOfBiometricData) obj2;
        }
        if (obj2 instanceof ASN1Integer) {
            return new TypeOfBiometricData(ASN1Integer.getInstance(obj2).intValueExact());
        }
        if (obj2 instanceof ASN1ObjectIdentifier) {
            return new TypeOfBiometricData(ASN1ObjectIdentifier.getInstance(obj2));
        }
        throw new IllegalArgumentException("unknown object in getInstance");
    }

    public TypeOfBiometricData(int predefinedBiometricType) {
        if (predefinedBiometricType == 0 || predefinedBiometricType == 1) {
            this.obj = new ASN1Integer((long) predefinedBiometricType);
            return;
        }
        throw new IllegalArgumentException("unknow PredefinedBiometricType : " + predefinedBiometricType);
    }

    public TypeOfBiometricData(ASN1ObjectIdentifier BiometricDataID) {
        this.obj = BiometricDataID;
    }

    public boolean isPredefined() {
        return this.obj instanceof ASN1Integer;
    }

    public int getPredefinedBiometricType() {
        return ((ASN1Integer) this.obj).intValueExact();
    }

    public ASN1ObjectIdentifier getBiometricDataOid() {
        return (ASN1ObjectIdentifier) this.obj;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.obj.toASN1Primitive();
    }
}
