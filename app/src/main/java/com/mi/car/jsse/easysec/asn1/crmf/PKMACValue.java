package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.cmp.CMPObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.cmp.PBMParameter;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class PKMACValue extends ASN1Object {
    private AlgorithmIdentifier algId;
    private ASN1BitString value;

    private PKMACValue(ASN1Sequence seq) {
        this.algId = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.value = ASN1BitString.getInstance(seq.getObjectAt(1));
    }

    public static PKMACValue getInstance(Object o) {
        if (o instanceof PKMACValue) {
            return (PKMACValue) o;
        }
        if (o != null) {
            return new PKMACValue(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public static PKMACValue getInstance(ASN1TaggedObject obj, boolean isExplicit) {
        return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
    }

    public PKMACValue(PBMParameter params, DERBitString value2) {
        this(new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, params), value2);
    }

    public PKMACValue(AlgorithmIdentifier aid, DERBitString value2) {
        this.algId = aid;
        this.value = value2;
    }

    public AlgorithmIdentifier getAlgId() {
        return this.algId;
    }

    public ASN1BitString getValue() {
        return this.value;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.algId);
        v.add(this.value);
        return new DERSequence(v);
    }
}
