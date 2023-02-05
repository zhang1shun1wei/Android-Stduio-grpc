package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class AuthorityInformationAccess extends ASN1Object {
    private AccessDescription[] descriptions;

    private static AccessDescription[] copy(AccessDescription[] descriptions2) {
        AccessDescription[] result = new AccessDescription[descriptions2.length];
        System.arraycopy(descriptions2, 0, result, 0, descriptions2.length);
        return result;
    }

    public static AuthorityInformationAccess getInstance(Object obj) {
        if (obj instanceof AuthorityInformationAccess) {
            return (AuthorityInformationAccess) obj;
        }
        if (obj != null) {
            return new AuthorityInformationAccess(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static AuthorityInformationAccess fromExtensions(Extensions extensions) {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.authorityInfoAccess));
    }

    private AuthorityInformationAccess(ASN1Sequence seq) {
        if (seq.size() < 1) {
            throw new IllegalArgumentException("sequence may not be empty");
        }
        this.descriptions = new AccessDescription[seq.size()];
        for (int i = 0; i != seq.size(); i++) {
            this.descriptions[i] = AccessDescription.getInstance(seq.getObjectAt(i));
        }
    }

    public AuthorityInformationAccess(AccessDescription description) {
        this.descriptions = new AccessDescription[]{description};
    }

    public AuthorityInformationAccess(AccessDescription[] descriptions2) {
        this.descriptions = copy(descriptions2);
    }

    public AuthorityInformationAccess(ASN1ObjectIdentifier oid, GeneralName location) {
        this(new AccessDescription(oid, location));
    }

    public AccessDescription[] getAccessDescriptions() {
        return copy(this.descriptions);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(this.descriptions);
    }

    public String toString() {
        return "AuthorityInformationAccess: Oid(" + this.descriptions[0].getAccessMethod().getId() + ")";
    }
}
