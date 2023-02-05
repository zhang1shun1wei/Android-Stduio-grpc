package com.mi.car.jsse.easysec.asn1.util;

import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import java.io.FileInputStream;

public class Dump {
    public static void main(String[] args) throws Exception {
        FileInputStream fIn = new FileInputStream(args[0]);
        try {
            ASN1InputStream bIn = new ASN1InputStream(fIn);
            while (true) {
                ASN1Primitive obj = bIn.readObject();
                if (obj != null) {
                    System.out.println(ASN1Dump.dumpAsString(obj));
                } else {
                    return;
                }
            }
        } finally {
            fIn.close();
        }
    }
}
