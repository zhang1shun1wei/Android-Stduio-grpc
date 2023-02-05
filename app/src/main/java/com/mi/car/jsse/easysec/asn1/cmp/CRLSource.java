//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.DistributionPointName;
import com.mi.car.jsse.easysec.asn1.x509.GeneralNames;

public class CRLSource extends ASN1Object implements ASN1Choice {
    private final DistributionPointName dpn;
    private final GeneralNames issuer;

    private CRLSource(ASN1TaggedObject ato) {
        switch(ato.getTagNo()) {
            case 0:
                this.dpn = DistributionPointName.getInstance(ato, true);
                this.issuer = null;
                break;
            case 1:
                this.dpn = null;
                this.issuer = GeneralNames.getInstance(ato, true);
                break;
            default:
                throw new IllegalArgumentException("unknown tag " + ato.getTagNo());
        }

    }

    public CRLSource(DistributionPointName dpn, GeneralNames issuer) {
        if (dpn != null && issuer != null) {
            throw new IllegalArgumentException("either dpn or issuer must be set");
        } else {
            this.dpn = dpn;
            this.issuer = issuer;
        }
    }

    public static CRLSource getInstance(Object o) {
        if (o instanceof CRLSource) {
            return (CRLSource)o;
        } else {
            return o != null ? new CRLSource(ASN1TaggedObject.getInstance(o)) : null;
        }
    }

    public DistributionPointName getDpn() {
        return this.dpn;
    }

    public GeneralNames getIssuer() {
        return this.issuer;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.dpn != null ? new DERTaggedObject(true, 0, this.dpn) : new DERTaggedObject(true, 1, this.issuer);
    }
}