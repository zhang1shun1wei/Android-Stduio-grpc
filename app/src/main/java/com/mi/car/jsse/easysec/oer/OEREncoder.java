package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import java.io.ByteArrayOutputStream;

public class OEREncoder {
    public static byte[] toByteArray(ASN1Encodable encodable, Element oerElement) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            new OEROutputStream(bos).write(encodable, oerElement);
            bos.flush();
            bos.close();
            return bos.toByteArray();
        } catch (Exception ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }
}
