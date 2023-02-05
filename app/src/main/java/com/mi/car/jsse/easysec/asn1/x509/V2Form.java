package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class V2Form extends ASN1Object {
    IssuerSerial baseCertificateID;
    GeneralNames issuerName;
    ObjectDigestInfo objectDigestInfo;

    public static V2Form getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static V2Form getInstance(Object obj) {
        if (obj instanceof V2Form) {
            return (V2Form) obj;
        }
        if (obj != null) {
            return new V2Form(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public V2Form(GeneralNames issuerName2) {
        this(issuerName2, null, null);
    }

    public V2Form(GeneralNames issuerName2, IssuerSerial baseCertificateID2) {
        this(issuerName2, baseCertificateID2, null);
    }

    public V2Form(GeneralNames issuerName2, ObjectDigestInfo objectDigestInfo2) {
        this(issuerName2, null, objectDigestInfo2);
    }

    public V2Form(GeneralNames issuerName2, IssuerSerial baseCertificateID2, ObjectDigestInfo objectDigestInfo2) {
        this.issuerName = issuerName2;
        this.baseCertificateID = baseCertificateID2;
        this.objectDigestInfo = objectDigestInfo2;
    }

    private V2Form(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        int index = 0;
        if (!(seq.getObjectAt(0) instanceof ASN1TaggedObject)) {
            index = 0 + 1;
            this.issuerName = GeneralNames.getInstance(seq.getObjectAt(0));
        }
        for (int i = index; i != seq.size(); i++) {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
            if (o.getTagNo() == 0) {
                this.baseCertificateID = IssuerSerial.getInstance(o, false);
            } else if (o.getTagNo() == 1) {
                this.objectDigestInfo = ObjectDigestInfo.getInstance(o, false);
            } else {
                throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
            }
        }
    }

    public GeneralNames getIssuerName() {
        return this.issuerName;
    }

    public IssuerSerial getBaseCertificateID() {
        return this.baseCertificateID;
    }

    public ObjectDigestInfo getObjectDigestInfo() {
        return this.objectDigestInfo;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (this.issuerName != null) {
            v.add(this.issuerName);
        }
        if (this.baseCertificateID != null) {
            v.add(new DERTaggedObject(false, 0, (ASN1Encodable) this.baseCertificateID));
        }
        if (this.objectDigestInfo != null) {
            v.add(new DERTaggedObject(false, 1, (ASN1Encodable) this.objectDigestInfo));
        }
        return new DERSequence(v);
    }
}
