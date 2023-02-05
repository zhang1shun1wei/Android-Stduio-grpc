package com.mi.car.jsse.easysec.asn1.x509.qualified;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;
import java.util.Enumeration;

public class MonetaryValue extends ASN1Object {
    private ASN1Integer amount;
    private Iso4217CurrencyCode currency;
    private ASN1Integer exponent;

    public static MonetaryValue getInstance(Object obj) {
        if (obj instanceof MonetaryValue) {
            return (MonetaryValue) obj;
        }
        if (obj != null) {
            return new MonetaryValue(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private MonetaryValue(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.currency = Iso4217CurrencyCode.getInstance(e.nextElement());
        this.amount = ASN1Integer.getInstance(e.nextElement());
        this.exponent = ASN1Integer.getInstance(e.nextElement());
    }

    public MonetaryValue(Iso4217CurrencyCode currency2, int amount2, int exponent2) {
        this.currency = currency2;
        this.amount = new ASN1Integer((long) amount2);
        this.exponent = new ASN1Integer((long) exponent2);
    }

    public Iso4217CurrencyCode getCurrency() {
        return this.currency;
    }

    public BigInteger getAmount() {
        return this.amount.getValue();
    }

    public BigInteger getExponent() {
        return this.exponent.getValue();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector(3);
        seq.add(this.currency);
        seq.add(this.amount);
        seq.add(this.exponent);
        return new DERSequence(seq);
    }
}
