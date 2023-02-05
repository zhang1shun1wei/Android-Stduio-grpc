package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class Holder extends ASN1Object {
    public static final int V1_CERTIFICATE_HOLDER = 0;
    public static final int V2_CERTIFICATE_HOLDER = 1;
    IssuerSerial baseCertificateID;
    GeneralNames entityName;
    ObjectDigestInfo objectDigestInfo;
    private int version;

    public static Holder getInstance(Object obj) {
        if (obj instanceof Holder) {
            return (Holder) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return new Holder(ASN1TaggedObject.getInstance(obj));
        }
        if (obj != null) {
            return new Holder(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private Holder(ASN1TaggedObject tagObj) {
        this.version = 1;
        switch (tagObj.getTagNo()) {
            case 0:
                this.baseCertificateID = IssuerSerial.getInstance(tagObj, true);
                break;
            case 1:
                this.entityName = GeneralNames.getInstance(tagObj, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag in Holder");
        }
        this.version = 0;
    }

    private Holder(ASN1Sequence seq) {
        this.version = 1;
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        for (int i = 0; i != seq.size(); i++) {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
            switch (tObj.getTagNo()) {
                case 0:
                    this.baseCertificateID = IssuerSerial.getInstance(tObj, false);
                    break;
                case 1:
                    this.entityName = GeneralNames.getInstance(tObj, false);
                    break;
                case 2:
                    this.objectDigestInfo = ObjectDigestInfo.getInstance(tObj, false);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag in Holder");
            }
        }
        this.version = 1;
    }

    public Holder(IssuerSerial baseCertificateID2) {
        this(baseCertificateID2, 1);
    }

    public Holder(IssuerSerial baseCertificateID2, int version2) {
        this.version = 1;
        this.baseCertificateID = baseCertificateID2;
        this.version = version2;
    }

    public int getVersion() {
        return this.version;
    }

    public Holder(GeneralNames entityName2) {
        this(entityName2, 1);
    }

    public Holder(GeneralNames entityName2, int version2) {
        this.version = 1;
        this.entityName = entityName2;
        this.version = version2;
    }

    public Holder(ObjectDigestInfo objectDigestInfo2) {
        this.version = 1;
        this.objectDigestInfo = objectDigestInfo2;
    }

    public IssuerSerial getBaseCertificateID() {
        return this.baseCertificateID;
    }

    public GeneralNames getEntityName() {
        return this.entityName;
    }

    public ObjectDigestInfo getObjectDigestInfo() {
        return this.objectDigestInfo;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        if (this.version == 1) {
            ASN1EncodableVector v = new ASN1EncodableVector(3);
            if (this.baseCertificateID != null) {
                v.add(new DERTaggedObject(false, 0, (ASN1Encodable) this.baseCertificateID));
            }
            if (this.entityName != null) {
                v.add(new DERTaggedObject(false, 1, (ASN1Encodable) this.entityName));
            }
            if (this.objectDigestInfo != null) {
                v.add(new DERTaggedObject(false, 2, (ASN1Encodable) this.objectDigestInfo));
            }
            return new DERSequence(v);
        } else if (this.entityName != null) {
            return new DERTaggedObject(true, 1, (ASN1Encodable) this.entityName);
        } else {
            return new DERTaggedObject(true, 0, (ASN1Encodable) this.baseCertificateID);
        }
    }
}
