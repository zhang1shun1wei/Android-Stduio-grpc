package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;

public class SinglePubInfo extends ASN1Object {
    public static final ASN1Integer dontCare = new ASN1Integer(0);
    public static final ASN1Integer ldap = new ASN1Integer(3);
    public static final ASN1Integer web = new ASN1Integer(2);
    public static final ASN1Integer x500 = new ASN1Integer(1);
    private GeneralName pubLocation;
    private ASN1Integer pubMethod;

    private SinglePubInfo(ASN1Sequence seq) {
        this.pubMethod = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2) {
            this.pubLocation = GeneralName.getInstance(seq.getObjectAt(1));
        }
    }

    public static SinglePubInfo getInstance(Object o) {
        if (o instanceof SinglePubInfo) {
            return (SinglePubInfo) o;
        }
        if (o != null) {
            return new SinglePubInfo(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public SinglePubInfo(ASN1Integer pubMethod2, GeneralName pubLocation2) {
        this.pubMethod = pubMethod2;
        this.pubLocation = pubLocation2;
    }

    public ASN1Integer getPubMethod() {
        return this.pubMethod;
    }

    public GeneralName getPubLocation() {
        return this.pubLocation;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.pubMethod);
        if (this.pubLocation != null) {
            v.add(this.pubLocation);
        }
        return new DERSequence(v);
    }
}
