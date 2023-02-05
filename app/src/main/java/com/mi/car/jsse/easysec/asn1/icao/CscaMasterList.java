package com.mi.car.jsse.easysec.asn1.icao;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERSet;
import com.mi.car.jsse.easysec.asn1.x509.Certificate;

public class CscaMasterList extends ASN1Object {
    private Certificate[] certList;
    private ASN1Integer version = new ASN1Integer(0);

    public static CscaMasterList getInstance(Object obj) {
        if (obj instanceof CscaMasterList) {
            return (CscaMasterList) obj;
        }
        if (obj != null) {
            return new CscaMasterList(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private CscaMasterList(ASN1Sequence seq) {
        if (seq == null || seq.size() == 0) {
            throw new IllegalArgumentException("null or empty sequence passed.");
        } else if (seq.size() != 2) {
            throw new IllegalArgumentException("Incorrect sequence size: " + seq.size());
        } else {
            this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
            ASN1Set certSet = ASN1Set.getInstance(seq.getObjectAt(1));
            this.certList = new Certificate[certSet.size()];
            for (int i = 0; i < this.certList.length; i++) {
                this.certList[i] = Certificate.getInstance(certSet.getObjectAt(i));
            }
        }
    }

    public CscaMasterList(Certificate[] certStructs) {
        this.certList = copyCertList(certStructs);
    }

    public int getVersion() {
        return this.version.intValueExact();
    }

    public Certificate[] getCertStructs() {
        return copyCertList(this.certList);
    }

    private Certificate[] copyCertList(Certificate[] orig) {
        Certificate[] certs = new Certificate[orig.length];
        for (int i = 0; i != certs.length; i++) {
            certs[i] = orig[i];
        }
        return certs;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector(2);
        seq.add(this.version);
        seq.add(new DERSet(this.certList));
        return new DERSequence(seq);
    }
}
