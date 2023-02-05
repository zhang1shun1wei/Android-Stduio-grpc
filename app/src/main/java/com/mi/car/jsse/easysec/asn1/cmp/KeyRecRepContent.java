//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.util.Enumeration;

public class KeyRecRepContent extends ASN1Object {
    private final PKIStatusInfo status;
    private CMPCertificate newSigCert;
    private ASN1Sequence caCerts;
    private ASN1Sequence keyPairHist;

    private KeyRecRepContent(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.status = PKIStatusInfo.getInstance(en.nextElement());

        while(en.hasMoreElements()) {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(en.nextElement());
            switch(tObj.getTagNo()) {
                case 0:
                    this.newSigCert = CMPCertificate.getInstance(tObj.getObject());
                    break;
                case 1:
                    this.caCerts = ASN1Sequence.getInstance(tObj.getObject());
                    break;
                case 2:
                    this.keyPairHist = ASN1Sequence.getInstance(tObj.getObject());
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }

    }

    public static KeyRecRepContent getInstance(Object o) {
        if (o instanceof KeyRecRepContent) {
            return (KeyRecRepContent)o;
        } else {
            return o != null ? new KeyRecRepContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public PKIStatusInfo getStatus() {
        return this.status;
    }

    public CMPCertificate getNewSigCert() {
        return this.newSigCert;
    }

    public CMPCertificate[] getCaCerts() {
        if (this.caCerts == null) {
            return null;
        } else {
            CMPCertificate[] results = new CMPCertificate[this.caCerts.size()];

            for(int i = 0; i != results.length; ++i) {
                results[i] = CMPCertificate.getInstance(this.caCerts.getObjectAt(i));
            }

            return results;
        }
    }

    public CertifiedKeyPair[] getKeyPairHist() {
        if (this.keyPairHist == null) {
            return null;
        } else {
            CertifiedKeyPair[] results = new CertifiedKeyPair[this.keyPairHist.size()];

            for(int i = 0; i != results.length; ++i) {
                results[i] = CertifiedKeyPair.getInstance(this.keyPairHist.getObjectAt(i));
            }

            return results;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.status);
        this.addOptional(v, 0, this.newSigCert);
        this.addOptional(v, 1, this.caCerts);
        this.addOptional(v, 2, this.keyPairHist);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }

    }
}