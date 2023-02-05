package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.util.encoders.Base64;
import java.io.IOException;
import java.io.InputStream;

public class PEMUtil {
    private final String _header1;
    private final String _header2;
    private final String _footer1;
    private final String _footer2;

    PEMUtil(String type) {
        this._header1 = "-----BEGIN " + type + "-----";
        this._header2 = "-----BEGIN X509 " + type + "-----";
        this._footer1 = "-----END " + type + "-----";
        this._footer2 = "-----END X509 " + type + "-----";
    }

    private String readLine(InputStream in) throws IOException {
        StringBuffer l = new StringBuffer();

        int c;
        do {
            while((c = in.read()) != 13 && c != 10 && c >= 0) {
                if (c != 13) {
                    l.append((char)c);
                }
            }
        } while(c >= 0 && l.length() == 0);

        return c < 0 ? null : l.toString();
    }

    ASN1Sequence readPEMObject(InputStream in) throws IOException {
        StringBuffer pemBuf = new StringBuffer();

        String line;
        while((line = this.readLine(in)) != null && !line.startsWith(this._header1) && !line.startsWith(this._header2)) {
        }

        while((line = this.readLine(in)) != null && !line.startsWith(this._footer1) && !line.startsWith(this._footer2)) {
            pemBuf.append(line);
        }

        if (pemBuf.length() != 0) {
            ASN1Primitive o = (new ASN1InputStream(Base64.decode(pemBuf.toString()))).readObject();
            if (!(o instanceof ASN1Sequence)) {
                throw new IOException("malformed PEM data encountered");
            } else {
                return (ASN1Sequence)o;
            }
        } else {
            return null;
        }
    }
}
