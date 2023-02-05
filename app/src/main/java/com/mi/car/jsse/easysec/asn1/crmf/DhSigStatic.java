package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.cms.IssuerAndSerialNumber;
import com.mi.car.jsse.easysec.util.Arrays;

public class DhSigStatic extends ASN1Object {
    private final ASN1OctetString hashValue;
    private final IssuerAndSerialNumber issuerAndSerial;

    public DhSigStatic(byte[] hashValue2) {
        this(null, hashValue2);
    }

    public DhSigStatic(IssuerAndSerialNumber issuerAndSerial2, byte[] hashValue2) {
        this.issuerAndSerial = issuerAndSerial2;
        this.hashValue = new DEROctetString(Arrays.clone(hashValue2));
    }

    public static DhSigStatic getInstance(Object o) {
        if (o instanceof DhSigStatic) {
            return (DhSigStatic) o;
        }
        if (o != null) {
            return new DhSigStatic(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private DhSigStatic(ASN1Sequence seq) {
        if (seq.size() == 1) {
            this.issuerAndSerial = null;
            this.hashValue = ASN1OctetString.getInstance(seq.getObjectAt(0));
        } else if (seq.size() == 2) {
            this.issuerAndSerial = IssuerAndSerialNumber.getInstance(seq.getObjectAt(0));
            this.hashValue = ASN1OctetString.getInstance(seq.getObjectAt(1));
        } else {
            throw new IllegalArgumentException("sequence wrong length for DhSigStatic");
        }
    }

    public IssuerAndSerialNumber getIssuerAndSerial() {
        return this.issuerAndSerial;
    }

    public byte[] getHashValue() {
        return Arrays.clone(this.hashValue.getOctets());
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.issuerAndSerial != null) {
            v.add(this.issuerAndSerial);
        }
        v.add(this.hashValue);
        return new DERSequence(v);
    }
}
