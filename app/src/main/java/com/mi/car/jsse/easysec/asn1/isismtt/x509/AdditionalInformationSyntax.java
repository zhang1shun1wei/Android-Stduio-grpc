package com.mi.car.jsse.easysec.asn1.isismtt.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.x500.DirectoryString;

public class AdditionalInformationSyntax extends ASN1Object {
    private DirectoryString information;

    public static AdditionalInformationSyntax getInstance(Object obj) {
        if (obj instanceof AdditionalInformationSyntax) {
            return (AdditionalInformationSyntax) obj;
        }
        if (obj != null) {
            return new AdditionalInformationSyntax(DirectoryString.getInstance(obj));
        }
        return null;
    }

    private AdditionalInformationSyntax(DirectoryString information2) {
        this.information = information2;
    }

    public AdditionalInformationSyntax(String information2) {
        this(new DirectoryString(information2));
    }

    public DirectoryString getInformation() {
        return this.information;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.information.toASN1Primitive();
    }
}
