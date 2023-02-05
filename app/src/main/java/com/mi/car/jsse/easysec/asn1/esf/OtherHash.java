package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class OtherHash extends ASN1Object implements ASN1Choice {
    private OtherHashAlgAndValue otherHash;
    private ASN1OctetString sha1Hash;

    public static OtherHash getInstance(Object obj) {
        if (obj instanceof OtherHash) {
            return (OtherHash) obj;
        }
        if (obj instanceof ASN1OctetString) {
            return new OtherHash((ASN1OctetString) obj);
        }
        return new OtherHash(OtherHashAlgAndValue.getInstance(obj));
    }

    private OtherHash(ASN1OctetString sha1Hash2) {
        this.sha1Hash = sha1Hash2;
    }

    public OtherHash(OtherHashAlgAndValue otherHash2) {
        this.otherHash = otherHash2;
    }

    public OtherHash(byte[] sha1Hash2) {
        this.sha1Hash = new DEROctetString(sha1Hash2);
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        if (this.otherHash == null) {
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
        }
        return this.otherHash.getHashAlgorithm();
    }

    public byte[] getHashValue() {
        if (this.otherHash == null) {
            return this.sha1Hash.getOctets();
        }
        return this.otherHash.getHashValue().getOctets();
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.otherHash == null) {
            return this.sha1Hash;
        }
        return this.otherHash.toASN1Primitive();
    }
}
