//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import java.io.IOException;

public class OtherStatusInfo extends ASN1Object implements ASN1Choice {
    private final CMCFailInfo failInfo;
    private final PendInfo pendInfo;
    private final ExtendedFailInfo extendedFailInfo;

    public static OtherStatusInfo getInstance(Object obj) {
        if (obj instanceof OtherStatusInfo) {
            return (OtherStatusInfo)obj;
        } else {
            if (obj instanceof ASN1Encodable) {
                ASN1Encodable asn1Value = ((ASN1Encodable)obj).toASN1Primitive();
                if (asn1Value instanceof ASN1Integer) {
                    return new OtherStatusInfo(CMCFailInfo.getInstance(asn1Value));
                }

                if (asn1Value instanceof ASN1Sequence) {
                    if (((ASN1Sequence)asn1Value).getObjectAt(0) instanceof ASN1ObjectIdentifier) {
                        return new OtherStatusInfo(ExtendedFailInfo.getInstance(asn1Value));
                    }

                    return new OtherStatusInfo(PendInfo.getInstance(asn1Value));
                }
            } else if (obj instanceof byte[]) {
                try {
                    return getInstance(ASN1Primitive.fromByteArray((byte[])((byte[])obj)));
                } catch (IOException var2) {
                    throw new IllegalArgumentException("parsing error: " + var2.getMessage());
                }
            }

            throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
        }
    }

    OtherStatusInfo(CMCFailInfo failInfo) {
        this(failInfo, (PendInfo)null, (ExtendedFailInfo)null);
    }

    OtherStatusInfo(PendInfo pendInfo) {
        this((CMCFailInfo)null, pendInfo, (ExtendedFailInfo)null);
    }

    OtherStatusInfo(ExtendedFailInfo extendedFailInfo) {
        this((CMCFailInfo)null, (PendInfo)null, extendedFailInfo);
    }

    private OtherStatusInfo(CMCFailInfo failInfo, PendInfo pendInfo, ExtendedFailInfo extendedFailInfo) {
        this.failInfo = failInfo;
        this.pendInfo = pendInfo;
        this.extendedFailInfo = extendedFailInfo;
    }

    public boolean isPendingInfo() {
        return this.pendInfo != null;
    }

    public boolean isFailInfo() {
        return this.failInfo != null;
    }

    public boolean isExtendedFailInfo() {
        return this.extendedFailInfo != null;
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.pendInfo != null) {
            return this.pendInfo.toASN1Primitive();
        } else {
            return this.failInfo != null ? this.failInfo.toASN1Primitive() : this.extendedFailInfo.toASN1Primitive();
        }
    }
}