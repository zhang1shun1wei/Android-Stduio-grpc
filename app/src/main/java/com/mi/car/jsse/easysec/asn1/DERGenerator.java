package com.mi.car.jsse.easysec.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public abstract class DERGenerator extends ASN1Generator {
    private boolean _isExplicit;
    private int _tagNo;
    private boolean _tagged;

    protected DERGenerator(OutputStream out) {
        super(out);
        this._tagged = false;
    }

    public DERGenerator(OutputStream out, int tagNo, boolean isExplicit) {
        super(out);
        this._tagged = false;
        this._tagged = true;
        this._isExplicit = isExplicit;
        this._tagNo = tagNo;
    }

    private void writeLength(OutputStream out, int length) throws IOException {
        if (length > 127) {
            int size = 1;
            int val = length;
            while (true) {
                val >>>= 8;
                if (val == 0) {
                    break;
                }
                size++;
            }
            out.write((byte) (size | 128));
            for (int i = (size - 1) * 8; i >= 0; i -= 8) {
                out.write((byte) (length >> i));
            }
            return;
        }
        out.write((byte) length);
    }

    /* access modifiers changed from: package-private */
    public void writeDEREncoded(OutputStream out, int tag, byte[] bytes) throws IOException {
        out.write(tag);
        writeLength(out, bytes.length);
        out.write(bytes);
    }

    /* access modifiers changed from: package-private */
    public void writeDEREncoded(int tag, byte[] bytes) throws IOException {
        if (this._tagged) {
            int tagNum = this._tagNo | 128;
            if (this._isExplicit) {
                int newTag = this._tagNo | 32 | 128;
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                writeDEREncoded(bOut, tag, bytes);
                writeDEREncoded(this._out, newTag, bOut.toByteArray());
            } else if ((tag & 32) != 0) {
                writeDEREncoded(this._out, tagNum | 32, bytes);
            } else {
                writeDEREncoded(this._out, tagNum, bytes);
            }
        } else {
            writeDEREncoded(this._out, tag, bytes);
        }
    }
}
