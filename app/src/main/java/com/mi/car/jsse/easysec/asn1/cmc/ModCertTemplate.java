//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Boolean;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.crmf.CertTemplate;

public class ModCertTemplate extends ASN1Object {
    private final BodyPartPath pkiDataReference;
    private final BodyPartList certReferences;
    private final boolean replace;
    private final CertTemplate certTemplate;

    public ModCertTemplate(BodyPartPath pkiDataReference, BodyPartList certReferences, boolean replace, CertTemplate certTemplate) {
        this.pkiDataReference = pkiDataReference;
        this.certReferences = certReferences;
        this.replace = replace;
        this.certTemplate = certTemplate;
    }

    private ModCertTemplate(ASN1Sequence seq) {
        if (seq.size() != 4 && seq.size() != 3) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.pkiDataReference = BodyPartPath.getInstance(seq.getObjectAt(0));
            this.certReferences = BodyPartList.getInstance(seq.getObjectAt(1));
            if (seq.size() == 4) {
                this.replace = ASN1Boolean.getInstance(seq.getObjectAt(2)).isTrue();
                this.certTemplate = CertTemplate.getInstance(seq.getObjectAt(3));
            } else {
                this.replace = true;
                this.certTemplate = CertTemplate.getInstance(seq.getObjectAt(2));
            }

        }
    }

    public static ModCertTemplate getInstance(Object o) {
        if (o instanceof ModCertTemplate) {
            return (ModCertTemplate)o;
        } else {
            return o != null ? new ModCertTemplate(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public BodyPartPath getPkiDataReference() {
        return this.pkiDataReference;
    }

    public BodyPartList getCertReferences() {
        return this.certReferences;
    }

    public boolean isReplacingFields() {
        return this.replace;
    }

    public CertTemplate getCertTemplate() {
        return this.certTemplate;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.pkiDataReference);
        v.add(this.certReferences);
        if (!this.replace) {
            v.add(ASN1Boolean.getInstance(this.replace));
        }

        v.add(this.certTemplate);
        return new DERSequence(v);
    }
}