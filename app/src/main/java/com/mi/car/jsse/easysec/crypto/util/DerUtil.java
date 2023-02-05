package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

class DerUtil {
    DerUtil() {
    }

    static ASN1OctetString getOctetString(byte[] data) {
        if (data == null) {
            return new DEROctetString(new byte[0]);
        }
        return new DEROctetString(Arrays.clone(data));
    }

    static byte[] toByteArray(ASN1Primitive primitive) {
        try {
            return primitive.getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("Cannot get encoding: " + e.getMessage()) {
                /* class com.mi.car.jsse.easysec.crypto.util.DerUtil.AnonymousClass1 */

                public Throwable getCause() {
                    return e;
                }
            };
        }
    }
}
