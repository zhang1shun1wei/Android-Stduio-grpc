package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import java.math.BigInteger;

public class X9IntegerConverter {
    public int getByteLength(ECCurve c) {
        return (c.getFieldSize() + 7) / 8;
    }

    public int getByteLength(ECFieldElement fe) {
        return (fe.getFieldSize() + 7) / 8;
    }

    public byte[] integerToBytes(BigInteger s, int qLength) {
        byte[] bytes = s.toByteArray();
        if (qLength < bytes.length) {
            byte[] tmp = new byte[qLength];
            System.arraycopy(bytes, bytes.length - tmp.length, tmp, 0, tmp.length);
            return tmp;
        } else if (qLength <= bytes.length) {
            return bytes;
        } else {
            byte[] tmp2 = new byte[qLength];
            System.arraycopy(bytes, 0, tmp2, tmp2.length - bytes.length, bytes.length);
            return tmp2;
        }
    }
}
