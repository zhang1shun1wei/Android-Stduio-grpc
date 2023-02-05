package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.util.Arrays;

public class X9ECPoint extends ASN1Object {
    private ECCurve c;
    private final ASN1OctetString encoding;
    private ECPoint p;

    public X9ECPoint(ECPoint p2, boolean compressed) {
        this.p = p2.normalize();
        this.encoding = new DEROctetString(p2.getEncoded(compressed));
    }

    public X9ECPoint(ECCurve c2, byte[] encoding2) {
        this.c = c2;
        this.encoding = new DEROctetString(Arrays.clone(encoding2));
    }

    public X9ECPoint(ECCurve c2, ASN1OctetString s) {
        this(c2, s.getOctets());
    }

    public byte[] getPointEncoding() {
        return Arrays.clone(this.encoding.getOctets());
    }

    public synchronized ECPoint getPoint() {
        if (this.p == null) {
            this.p = this.c.decodePoint(this.encoding.getOctets()).normalize();
        }
        return this.p;
    }

    public boolean isPointCompressed() {
        byte[] octets = this.encoding.getOctets();
        if (octets == null || octets.length <= 0) {
            return false;
        }
        if (octets[0] == 2 || octets[0] == 3) {
            return true;
        }
        return false;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.encoding;
    }
}
