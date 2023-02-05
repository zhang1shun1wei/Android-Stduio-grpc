//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.bc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.DigestInfo;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import com.mi.car.jsse.easysec.asn1.x509.GeneralNames;

public class LinkedCertificate extends ASN1Object {
    private final DigestInfo digest;
    private final GeneralName certLocation;
    private X500Name certIssuer;
    private GeneralNames cACerts;

    public LinkedCertificate(DigestInfo digest, GeneralName certLocation) {
        this(digest, certLocation, (X500Name)null, (GeneralNames)null);
    }

    public LinkedCertificate(DigestInfo digest, GeneralName certLocation, X500Name certIssuer, GeneralNames cACerts) {
        this.digest = digest;
        this.certLocation = certLocation;
        this.certIssuer = certIssuer;
        this.cACerts = cACerts;
    }

    private LinkedCertificate(ASN1Sequence seq) {
        this.digest = DigestInfo.getInstance(seq.getObjectAt(0));
        this.certLocation = GeneralName.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            for(int i = 2; i != seq.size(); ++i) {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
                switch(tagged.getTagNo()) {
                    case 0:
                        this.certIssuer = X500Name.getInstance(tagged, false);
                        break;
                    case 1:
                        this.cACerts = GeneralNames.getInstance(tagged, false);
                        break;
                    default:
                        throw new IllegalArgumentException("unknown tag in tagged field");
                }
            }
        }

    }

    public static LinkedCertificate getInstance(Object o) {
        if (o instanceof LinkedCertificate) {
            return (LinkedCertificate)o;
        } else {
            return o != null ? new LinkedCertificate(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public DigestInfo getDigest() {
        return this.digest;
    }

    public GeneralName getCertLocation() {
        return this.certLocation;
    }

    public X500Name getCertIssuer() {
        return this.certIssuer;
    }

    public GeneralNames getCACerts() {
        return this.cACerts;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.digest);
        v.add(this.certLocation);
        if (this.certIssuer != null) {
            v.add(new DERTaggedObject(false, 0, this.certIssuer));
        }

        if (this.cACerts != null) {
            v.add(new DERTaggedObject(false, 1, this.cACerts));
        }

        return new DERSequence(v);
    }
}