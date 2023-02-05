package com.mi.car.jsse.easysec.asn1.icao;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1PrintableString;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERPrintableString;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class LDSVersionInfo extends ASN1Object {
    private ASN1PrintableString ldsVersion;
    private ASN1PrintableString unicodeVersion;

    public LDSVersionInfo(String ldsVersion2, String unicodeVersion2) {
        this.ldsVersion = new DERPrintableString(ldsVersion2);
        this.unicodeVersion = new DERPrintableString(unicodeVersion2);
    }

    private LDSVersionInfo(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("sequence wrong size for LDSVersionInfo");
        }
        this.ldsVersion = ASN1PrintableString.getInstance(seq.getObjectAt(0));
        this.unicodeVersion = ASN1PrintableString.getInstance(seq.getObjectAt(1));
    }

    public static LDSVersionInfo getInstance(Object obj) {
        if (obj instanceof LDSVersionInfo) {
            return (LDSVersionInfo) obj;
        }
        if (obj != null) {
            return new LDSVersionInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public String getLdsVersion() {
        return this.ldsVersion.getString();
    }

    public String getUnicodeVersion() {
        return this.unicodeVersion.getString();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.ldsVersion);
        v.add(this.unicodeVersion);
        return new DERSequence(v);
    }
}
