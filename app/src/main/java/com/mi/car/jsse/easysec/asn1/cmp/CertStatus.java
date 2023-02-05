//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.math.BigInteger;

public class CertStatus extends ASN1Object {
    private final ASN1OctetString certHash;
    private final ASN1Integer certReqId;
    private PKIStatusInfo statusInfo;
    private AlgorithmIdentifier hashAlg;

    private CertStatus(ASN1Sequence seq) {
        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        this.certReqId = ASN1Integer.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            for(int t = 2; t < seq.size(); ++t) {
                ASN1Encodable o = seq.getObjectAt(t);
                if (o.toASN1Primitive() instanceof ASN1Sequence) {
                    this.statusInfo = PKIStatusInfo.getInstance(o);
                }

                if (o.toASN1Primitive() instanceof ASN1TaggedObject) {
                    ASN1TaggedObject dto = DERTaggedObject.getInstance(seq.getObjectAt(3));
                    if (dto.getTagNo() != 0) {
                        throw new IllegalArgumentException("unknown tag " + dto.getTagNo());
                    }

                    this.hashAlg = AlgorithmIdentifier.getInstance(dto, true);
                }
            }
        }

    }

    public CertStatus(byte[] certHash, BigInteger certReqId) {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = new ASN1Integer(certReqId);
    }

    public CertStatus(byte[] certHash, BigInteger certReqId, PKIStatusInfo statusInfo) {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = new ASN1Integer(certReqId);
        this.statusInfo = statusInfo;
    }

    public CertStatus(byte[] certHash, BigInteger certReqId, PKIStatusInfo statusInfo, AlgorithmIdentifier hashAlg) {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = new ASN1Integer(certReqId);
        this.statusInfo = statusInfo;
        this.hashAlg = hashAlg;
    }

    public static CertStatus getInstance(Object o) {
        if (o instanceof CertStatus) {
            return (CertStatus)o;
        } else {
            return o != null ? new CertStatus(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1OctetString getCertHash() {
        return this.certHash;
    }

    public ASN1Integer getCertReqId() {
        return this.certReqId;
    }

    public PKIStatusInfo getStatusInfo() {
        return this.statusInfo;
    }

    public AlgorithmIdentifier getHashAlg() {
        return this.hashAlg;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.certHash);
        v.add(this.certReqId);
        if (this.statusInfo != null) {
            v.add(this.statusInfo);
        }

        if (this.hashAlg != null) {
            v.add(new DERTaggedObject(true, 0, this.hashAlg));
        }

        return new DERSequence(v);
    }
}