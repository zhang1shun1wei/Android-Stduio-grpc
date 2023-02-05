package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1PrintableString;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.io.IOException;

public abstract class X509NameEntryConverter {
    public abstract ASN1Primitive getConvertedValue(ASN1ObjectIdentifier aSN1ObjectIdentifier, String str);

    /* access modifiers changed from: protected */
    public ASN1Primitive convertHexEncoded(String str, int off) throws IOException {
        return ASN1Primitive.fromByteArray(Hex.decodeStrict(str, off, str.length() - off));
    }

    /* access modifiers changed from: protected */
    public boolean canBePrintable(String str) {
        return ASN1PrintableString.isPrintableString(str);
    }
}
