//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.util.Enumeration;

public class PKIMessage extends ASN1Object {
    private final PKIHeader header;
    private final PKIBody body;
    private ASN1BitString protection;
    private ASN1Sequence extraCerts;

    private PKIMessage(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.header = PKIHeader.getInstance(en.nextElement());
        this.body = PKIBody.getInstance(en.nextElement());

        while(en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();
            if (tObj.getTagNo() == 0) {
                this.protection = DERBitString.getInstance(tObj, true);
            } else {
                this.extraCerts = ASN1Sequence.getInstance(tObj, true);
            }
        }

    }

    public PKIMessage(PKIHeader header, PKIBody body, ASN1BitString protection, CMPCertificate[] extraCerts) {
        this.header = header;
        this.body = body;
        this.protection = protection;
        if (extraCerts != null) {
            this.extraCerts = new DERSequence(extraCerts);
        }

    }

    public PKIMessage(PKIHeader header, PKIBody body, ASN1BitString protection) {
        this(header, body, protection, (CMPCertificate[])null);
    }

    public PKIMessage(PKIHeader header, PKIBody body) {
        this(header, body, (ASN1BitString)null, (CMPCertificate[])null);
    }

    public static PKIMessage getInstance(Object o) {
        if (o instanceof PKIMessage) {
            return (PKIMessage)o;
        } else {
            return o != null ? new PKIMessage(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public PKIHeader getHeader() {
        return this.header;
    }

    public PKIBody getBody() {
        return this.body;
    }

    public ASN1BitString getProtection() {
        return this.protection;
    }

    public CMPCertificate[] getExtraCerts() {
        if (this.extraCerts == null) {
            return null;
        } else {
            CMPCertificate[] results = new CMPCertificate[this.extraCerts.size()];

            for(int i = 0; i < results.length; ++i) {
                results[i] = CMPCertificate.getInstance(this.extraCerts.getObjectAt(i));
            }

            return results;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.header);
        v.add(this.body);
        this.addOptional(v, 0, this.protection);
        this.addOptional(v, 1, this.extraCerts);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }

    }
}
