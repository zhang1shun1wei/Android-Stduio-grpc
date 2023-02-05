//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import java.math.BigInteger;

public class GetCert extends ASN1Object {
    private final GeneralName issuerName;
    private final BigInteger serialNumber;

    private GetCert(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.issuerName = GeneralName.getInstance(seq.getObjectAt(0));
            this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        }
    }

    public GetCert(GeneralName issuerName, BigInteger serialNumber) {
        this.issuerName = issuerName;
        this.serialNumber = serialNumber;
    }

    public static GetCert getInstance(Object o) {
        if (o instanceof GetCert) {
            return (GetCert)o;
        } else {
            return o != null ? new GetCert(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public GeneralName getIssuerName() {
        return this.issuerName;
    }

    public BigInteger getSerialNumber() {
        return this.serialNumber;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.issuerName);
        v.add(new ASN1Integer(this.serialNumber));
        return new DERSequence(v);
    }
}