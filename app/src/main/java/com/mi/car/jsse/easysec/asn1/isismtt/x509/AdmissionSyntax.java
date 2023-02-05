package com.mi.car.jsse.easysec.asn1.isismtt.x509;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import java.util.Enumeration;

public class AdmissionSyntax extends ASN1Object {
    private GeneralName admissionAuthority;
    private ASN1Sequence contentsOfAdmissions;

    public static AdmissionSyntax getInstance(Object obj) {
        if (obj == null || (obj instanceof AdmissionSyntax)) {
            return (AdmissionSyntax) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new AdmissionSyntax((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private AdmissionSyntax(ASN1Sequence seq) {
        switch (seq.size()) {
            case 1:
                this.contentsOfAdmissions = DERSequence.getInstance(seq.getObjectAt(0));
                return;
            case 2:
                this.admissionAuthority = GeneralName.getInstance(seq.getObjectAt(0));
                this.contentsOfAdmissions = DERSequence.getInstance(seq.getObjectAt(1));
                return;
            default:
                throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
    }

    public AdmissionSyntax(GeneralName admissionAuthority2, ASN1Sequence contentsOfAdmissions2) {
        this.admissionAuthority = admissionAuthority2;
        this.contentsOfAdmissions = contentsOfAdmissions2;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(2);
        if (this.admissionAuthority != null) {
            vec.add(this.admissionAuthority);
        }
        vec.add(this.contentsOfAdmissions);
        return new DERSequence(vec);
    }

    public GeneralName getAdmissionAuthority() {
        return this.admissionAuthority;
    }

    public Admissions[] getContentsOfAdmissions() {
        Admissions[] admissions = new Admissions[this.contentsOfAdmissions.size()];
        int count = 0;
        Enumeration e = this.contentsOfAdmissions.getObjects();
        while (e.hasMoreElements()) {
            admissions[count] = Admissions.getInstance(e.nextElement());
            count++;
        }
        return admissions;
    }
}
