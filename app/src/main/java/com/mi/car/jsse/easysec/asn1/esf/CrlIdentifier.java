package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTCTime;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import java.math.BigInteger;

public class CrlIdentifier extends ASN1Object {
    private ASN1UTCTime crlIssuedTime;
    private X500Name crlIssuer;
    private ASN1Integer crlNumber;

    public static CrlIdentifier getInstance(Object obj) {
        if (obj instanceof CrlIdentifier) {
            return (CrlIdentifier) obj;
        }
        if (obj != null) {
            return new CrlIdentifier(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private CrlIdentifier(ASN1Sequence seq) {
        if (seq.size() < 2 || seq.size() > 3) {
            throw new IllegalArgumentException();
        }
        this.crlIssuer = X500Name.getInstance(seq.getObjectAt(0));
        this.crlIssuedTime = ASN1UTCTime.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            this.crlNumber = ASN1Integer.getInstance(seq.getObjectAt(2));
        }
    }

    public CrlIdentifier(X500Name crlIssuer2, ASN1UTCTime crlIssuedTime2) {
        this(crlIssuer2, crlIssuedTime2, null);
    }

    public CrlIdentifier(X500Name crlIssuer2, ASN1UTCTime crlIssuedTime2, BigInteger crlNumber2) {
        this.crlIssuer = crlIssuer2;
        this.crlIssuedTime = crlIssuedTime2;
        if (crlNumber2 != null) {
            this.crlNumber = new ASN1Integer(crlNumber2);
        }
    }

    public X500Name getCrlIssuer() {
        return this.crlIssuer;
    }

    public ASN1UTCTime getCrlIssuedTime() {
        return this.crlIssuedTime;
    }

    public BigInteger getCrlNumber() {
        if (this.crlNumber == null) {
            return null;
        }
        return this.crlNumber.getValue();
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.crlIssuer.toASN1Primitive());
        v.add(this.crlIssuedTime);
        if (this.crlNumber != null) {
            v.add(this.crlNumber);
        }
        return new DERSequence(v);
    }
}
