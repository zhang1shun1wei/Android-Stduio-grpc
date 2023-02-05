package com.mi.car.jsse.easysec.asn1.icao;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class DataGroupHash extends ASN1Object {
    ASN1OctetString dataGroupHashValue;
    ASN1Integer dataGroupNumber;

    public static DataGroupHash getInstance(Object obj) {
        if (obj instanceof DataGroupHash) {
            return (DataGroupHash) obj;
        }
        if (obj != null) {
            return new DataGroupHash(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private DataGroupHash(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.dataGroupNumber = ASN1Integer.getInstance(e.nextElement());
        this.dataGroupHashValue = ASN1OctetString.getInstance(e.nextElement());
    }

    public DataGroupHash(int dataGroupNumber2, ASN1OctetString dataGroupHashValue2) {
        this.dataGroupNumber = new ASN1Integer((long) dataGroupNumber2);
        this.dataGroupHashValue = dataGroupHashValue2;
    }

    public int getDataGroupNumber() {
        return this.dataGroupNumber.intValueExact();
    }

    public ASN1OctetString getDataGroupHashValue() {
        return this.dataGroupHashValue;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector(2);
        seq.add(this.dataGroupNumber);
        seq.add(this.dataGroupHashValue);
        return new DERSequence(seq);
    }
}
