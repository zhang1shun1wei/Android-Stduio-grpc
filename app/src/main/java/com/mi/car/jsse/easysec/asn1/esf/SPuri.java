package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DERIA5String;

public class SPuri {
    private ASN1IA5String uri;

    public static SPuri getInstance(Object obj) {
        if (obj instanceof SPuri) {
            return (SPuri)obj;
        } else {
            return obj instanceof ASN1IA5String ? new SPuri(ASN1IA5String.getInstance(obj)) : null;
        }
    }

    public SPuri(ASN1IA5String uri) {
        this.uri = uri;
    }

    /** @deprecated */
    public DERIA5String getUri() {
        return null != this.uri && !(this.uri instanceof DERIA5String) ? new DERIA5String(this.uri.getString(), false) : (DERIA5String)this.uri;
    }

    public ASN1IA5String getUriIA5() {
        return this.uri;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.uri.toASN1Primitive();
    }
}
