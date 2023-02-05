//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.crmf.CertId;
import com.mi.car.jsse.easysec.asn1.x509.CertificateList;

public class RevRepContentBuilder {
    private final ASN1EncodableVector status = new ASN1EncodableVector();
    private final ASN1EncodableVector revCerts = new ASN1EncodableVector();
    private final ASN1EncodableVector crls = new ASN1EncodableVector();

    public RevRepContentBuilder() {
    }

    public RevRepContentBuilder add(PKIStatusInfo status) {
        this.status.add(status);
        return this;
    }

    public RevRepContentBuilder add(PKIStatusInfo status, CertId certId) {
        if (this.status.size() != this.revCerts.size()) {
            throw new IllegalStateException("status and revCerts sequence must be in common order");
        } else {
            this.status.add(status);
            this.revCerts.add(certId);
            return this;
        }
    }

    public RevRepContentBuilder addCrl(CertificateList crl) {
        this.crls.add(crl);
        return this;
    }

    public RevRepContent build() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(new DERSequence(this.status));
        if (this.revCerts.size() != 0) {
            v.add(new DERTaggedObject(true, 0, new DERSequence(this.revCerts)));
        }

        if (this.crls.size() != 0) {
            v.add(new DERTaggedObject(true, 1, new DERSequence(this.crls)));
        }

        return RevRepContent.getInstance(new DERSequence(v));
    }
}
