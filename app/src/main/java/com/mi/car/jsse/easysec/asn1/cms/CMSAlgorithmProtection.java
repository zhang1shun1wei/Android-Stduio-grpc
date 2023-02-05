//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class CMSAlgorithmProtection extends ASN1Object {
    public static final int SIGNATURE = 1;
    public static final int MAC = 2;
    private final AlgorithmIdentifier digestAlgorithm;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final AlgorithmIdentifier macAlgorithm;

    public CMSAlgorithmProtection(AlgorithmIdentifier digestAlgorithm, int type, AlgorithmIdentifier algorithmIdentifier) {
        if (digestAlgorithm != null && algorithmIdentifier != null) {
            this.digestAlgorithm = digestAlgorithm;
            if (type == 1) {
                this.signatureAlgorithm = algorithmIdentifier;
                this.macAlgorithm = null;
            } else {
                if (type != 2) {
                    throw new IllegalArgumentException("Unknown type: " + type);
                }

                this.signatureAlgorithm = null;
                this.macAlgorithm = algorithmIdentifier;
            }

        } else {
            throw new NullPointerException("AlgorithmIdentifiers cannot be null");
        }
    }

    private CMSAlgorithmProtection(ASN1Sequence sequence) {
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("Sequence wrong size: One of signatureAlgorithm or macAlgorithm must be present");
        } else {
            this.digestAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(sequence.getObjectAt(1));
            if (tagged.getTagNo() == 1) {
                this.signatureAlgorithm = AlgorithmIdentifier.getInstance(tagged, false);
                this.macAlgorithm = null;
            } else {
                if (tagged.getTagNo() != 2) {
                    throw new IllegalArgumentException("Unknown tag found: " + tagged.getTagNo());
                }

                this.signatureAlgorithm = null;
                this.macAlgorithm = AlgorithmIdentifier.getInstance(tagged, false);
            }

        }
    }

    public static CMSAlgorithmProtection getInstance(Object obj) {
        if (obj instanceof CMSAlgorithmProtection) {
            return (CMSAlgorithmProtection)obj;
        } else {
            return obj != null ? new CMSAlgorithmProtection(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return this.digestAlgorithm;
    }

    public AlgorithmIdentifier getMacAlgorithm() {
        return this.macAlgorithm;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.digestAlgorithm);
        if (this.signatureAlgorithm != null) {
            v.add(new DERTaggedObject(false, 1, this.signatureAlgorithm));
        }

        if (this.macAlgorithm != null) {
            v.add(new DERTaggedObject(false, 2, this.macAlgorithm));
        }

        return new DERSequence(v);
    }
}
