package com.mi.car.jsse.easysec.asn1.x509.qualified;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class QCStatement extends ASN1Object implements ETSIQCObjectIdentifiers, RFC3739QCObjectIdentifiers {
    ASN1ObjectIdentifier qcStatementId;
    ASN1Encodable qcStatementInfo;

    public static QCStatement getInstance(Object obj) {
        if (obj instanceof QCStatement) {
            return (QCStatement) obj;
        }
        if (obj != null) {
            return new QCStatement(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private QCStatement(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.qcStatementId = ASN1ObjectIdentifier.getInstance(e.nextElement());
        if (e.hasMoreElements()) {
            this.qcStatementInfo = (ASN1Encodable) e.nextElement();
        }
    }

    public QCStatement(ASN1ObjectIdentifier qcStatementId2) {
        this.qcStatementId = qcStatementId2;
        this.qcStatementInfo = null;
    }

    public QCStatement(ASN1ObjectIdentifier qcStatementId2, ASN1Encodable qcStatementInfo2) {
        this.qcStatementId = qcStatementId2;
        this.qcStatementInfo = qcStatementInfo2;
    }

    public ASN1ObjectIdentifier getStatementId() {
        return this.qcStatementId;
    }

    public ASN1Encodable getStatementInfo() {
        return this.qcStatementInfo;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector(2);
        seq.add(this.qcStatementId);
        if (this.qcStatementInfo != null) {
            seq.add(this.qcStatementInfo);
        }
        return new DERSequence(seq);
    }
}
