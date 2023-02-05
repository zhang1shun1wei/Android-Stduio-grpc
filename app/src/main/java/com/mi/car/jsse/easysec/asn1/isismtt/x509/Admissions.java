package com.mi.car.jsse.easysec.asn1.isismtt.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import java.util.Enumeration;

public class Admissions extends ASN1Object {
    private GeneralName admissionAuthority;
    private NamingAuthority namingAuthority;
    private ASN1Sequence professionInfos;

    public static Admissions getInstance(Object obj) {
        if (obj == null || (obj instanceof Admissions)) {
            return (Admissions) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new Admissions((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private Admissions(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        ASN1Encodable o = (ASN1Encodable) e.nextElement();
        if (o instanceof ASN1TaggedObject) {
            switch (((ASN1TaggedObject) o).getTagNo()) {
                case 0:
                    this.admissionAuthority = GeneralName.getInstance((ASN1TaggedObject) o, true);
                    break;
                case 1:
                    this.namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject) o, true);
                    break;
                default:
                    throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject) o).getTagNo());
            }
            o = (ASN1Encodable) e.nextElement();
        }
        if (o instanceof ASN1TaggedObject) {
            switch (((ASN1TaggedObject) o).getTagNo()) {
                default:
                    throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject) o).getTagNo());
                case 1:
                    this.namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject) o, true);
                    o = (ASN1Encodable) e.nextElement();
                    break;
            }
        }
        this.professionInfos = ASN1Sequence.getInstance(o);
        if (e.hasMoreElements()) {
            throw new IllegalArgumentException("Bad object encountered: " + e.nextElement().getClass());
        }
    }

    public Admissions(GeneralName admissionAuthority2, NamingAuthority namingAuthority2, ProfessionInfo[] professionInfos2) {
        this.admissionAuthority = admissionAuthority2;
        this.namingAuthority = namingAuthority2;
        this.professionInfos = new DERSequence(professionInfos2);
    }

    public GeneralName getAdmissionAuthority() {
        return this.admissionAuthority;
    }

    public NamingAuthority getNamingAuthority() {
        return this.namingAuthority;
    }

    public ProfessionInfo[] getProfessionInfos() {
        ProfessionInfo[] infos = new ProfessionInfo[this.professionInfos.size()];
        int count = 0;
        Enumeration e = this.professionInfos.getObjects();
        while (e.hasMoreElements()) {
            infos[count] = ProfessionInfo.getInstance(e.nextElement());
            count++;
        }
        return infos;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(3);
        if (this.admissionAuthority != null) {
            vec.add(new DERTaggedObject(true, 0, this.admissionAuthority));
        }
        if (this.namingAuthority != null) {
            vec.add(new DERTaggedObject(true, 1, this.namingAuthority));
        }
        vec.add(this.professionInfos);
        return new DERSequence(vec);
    }
}
