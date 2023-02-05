package com.mi.car.jsse.easysec.asn1.x500;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x500.style.BCStyle;
import java.util.Enumeration;

public class X500Name extends ASN1Object implements ASN1Choice {
    private static X500NameStyle defaultStyle = BCStyle.INSTANCE;
    private int hashCodeValue;
    private boolean isHashCodeCalculated;
    private DERSequence rdnSeq;
    private RDN[] rdns;
    private X500NameStyle style;

    public X500Name(X500NameStyle style2, X500Name name) {
        this.style = style2;
        this.rdns = name.rdns;
        this.rdnSeq = name.rdnSeq;
    }

    public static X500Name getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, true));
    }

    public static X500Name getInstance(Object obj) {
        if (obj instanceof X500Name) {
            return (X500Name) obj;
        }
        if (obj != null) {
            return new X500Name(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static X500Name getInstance(X500NameStyle style2, Object obj) {
        if (obj instanceof X500Name) {
            return new X500Name(style2, (X500Name) obj);
        }
        if (obj != null) {
            return new X500Name(style2, ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private X500Name(ASN1Sequence seq) {
        this(defaultStyle, seq);
    }

    private X500Name(X500NameStyle style2, ASN1Sequence seq) {
        this.style = style2;
        this.rdns = new RDN[seq.size()];
        boolean inPlace = true;
        int index = 0;
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            Object element = e.nextElement();
            RDN rdn = RDN.getInstance(element);
            inPlace &= rdn == element;
            this.rdns[index] = rdn;
            index++;
        }
        if (inPlace) {
            this.rdnSeq = DERSequence.convert(seq);
        } else {
            this.rdnSeq = new DERSequence(this.rdns);
        }
    }

    public X500Name(RDN[] rDNs) {
        this(defaultStyle, rDNs);
    }

    public X500Name(X500NameStyle style2, RDN[] rDNs) {
        this.style = style2;
        this.rdns = (RDN[]) rDNs.clone();
        this.rdnSeq = new DERSequence(this.rdns);
    }

    public X500Name(String dirName) {
        this(defaultStyle, dirName);
    }

    public X500Name(X500NameStyle style2, String dirName) {
        this(style2.fromString(dirName));
        this.style = style2;
    }

    public RDN[] getRDNs() {
        return (RDN[]) this.rdns.clone();
    }

    public ASN1ObjectIdentifier[] getAttributeTypes() {
        int count = this.rdns.length;
        int totalSize = 0;
        for (int i = 0; i < count; i++) {
            totalSize += this.rdns[i].size();
        }
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[totalSize];
        int oidsOff = 0;
        for (int i2 = 0; i2 < count; i2++) {
            oidsOff += this.rdns[i2].collectAttributeTypes(oids, oidsOff);
        }
        return oids;
    }

    public RDN[] getRDNs(ASN1ObjectIdentifier attributeType) {
        RDN[] res = new RDN[this.rdns.length];
        int count = 0;
        for (int i = 0; i != this.rdns.length; i++) {
            RDN rdn = this.rdns[i];
            if (rdn.containsAttributeType(attributeType)) {
                res[count] = rdn;
                count++;
            }
        }
        if (count >= res.length) {
            return res;
        }
        RDN[] tmp = new RDN[count];
        System.arraycopy(res, 0, tmp, 0, tmp.length);
        return tmp;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.rdnSeq;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public int hashCode() {
        if (this.isHashCodeCalculated) {
            return this.hashCodeValue;
        }
        this.isHashCodeCalculated = true;
        this.hashCodeValue = this.style.calculateHashCode(this);
        return this.hashCodeValue;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof X500Name) && !(obj instanceof ASN1Sequence)) {
            return false;
        }
        if (toASN1Primitive().equals(((ASN1Encodable) obj).toASN1Primitive())) {
            return true;
        }
        try {
            return this.style.areEqual(this, new X500Name(ASN1Sequence.getInstance(((ASN1Encodable) obj).toASN1Primitive())));
        } catch (Exception e) {
            return false;
        }
    }

    public String toString() {
        return this.style.toString(this);
    }

    public static void setDefaultStyle(X500NameStyle style2) {
        if (style2 == null) {
            throw new NullPointerException("cannot set style to null");
        }
        defaultStyle = style2;
    }

    public static X500NameStyle getDefaultStyle() {
        return defaultStyle;
    }
}
