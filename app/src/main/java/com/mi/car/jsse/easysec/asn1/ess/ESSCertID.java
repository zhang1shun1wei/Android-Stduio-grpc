package com.mi.car.jsse.easysec.asn1.ess;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.IssuerSerial;
import com.mi.car.jsse.easysec.util.Arrays;

public class ESSCertID extends ASN1Object {
    private ASN1OctetString certHash;
    private IssuerSerial issuerSerial;

    public static ESSCertID getInstance(Object o) {
        if (o instanceof ESSCertID) {
            return (ESSCertID) o;
        }
        if (o != null) {
            return new ESSCertID(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private ESSCertID(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(1));
        }
    }

    public ESSCertID(byte[] hash) {
        this.certHash = new DEROctetString(Arrays.clone(hash));
    }

    public ESSCertID(byte[] hash, IssuerSerial issuerSerial2) {
        this.certHash = new DEROctetString(Arrays.clone(hash));
        this.issuerSerial = issuerSerial2;
    }

    public byte[] getCertHash() {
        return this.certHash.getOctets();
    }

    public IssuerSerial getIssuerSerial() {
        return this.issuerSerial;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.certHash);
        if (this.issuerSerial != null) {
            v.add(this.issuerSerial);
        }
        return new DERSequence(v);
    }
}
