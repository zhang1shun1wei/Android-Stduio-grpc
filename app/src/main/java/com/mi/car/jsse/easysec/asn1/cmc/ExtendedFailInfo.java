//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class ExtendedFailInfo extends ASN1Object {
    private final ASN1ObjectIdentifier failInfoOID;
    private final ASN1Encodable failInfoValue;

    public ExtendedFailInfo(ASN1ObjectIdentifier failInfoOID, ASN1Encodable failInfoValue) {
        this.failInfoOID = failInfoOID;
        this.failInfoValue = failInfoValue;
    }

    private ExtendedFailInfo(ASN1Sequence s) {
        if (s.size() != 2) {
            throw new IllegalArgumentException("Sequence must be 2 elements.");
        } else {
            this.failInfoOID = ASN1ObjectIdentifier.getInstance(s.getObjectAt(0));
            this.failInfoValue = s.getObjectAt(1);
        }
    }

    public static ExtendedFailInfo getInstance(Object obj) {
        if (obj instanceof ExtendedFailInfo) {
            return (ExtendedFailInfo)obj;
        } else {
            if (obj instanceof ASN1Encodable) {
                ASN1Encodable asn1Value = ((ASN1Encodable)obj).toASN1Primitive();
                if (asn1Value instanceof ASN1Sequence) {
                    return new ExtendedFailInfo((ASN1Sequence)asn1Value);
                }
            } else if (obj instanceof byte[]) {
                return getInstance(ASN1Sequence.getInstance(obj));
            }

            return null;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.failInfoOID, this.failInfoValue});
    }

    public ASN1ObjectIdentifier getFailInfoOID() {
        return this.failInfoOID;
    }

    public ASN1Encodable getFailInfoValue() {
        return this.failInfoValue;
    }
}