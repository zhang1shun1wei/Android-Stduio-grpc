package com.mi.car.jsse.easysec.util.io.pem;

import com.mi.car.jsse.easysec.util.Strings;
import com.mi.car.jsse.easysec.util.encoders.Base64;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Iterator;

public class PemWriter extends BufferedWriter {
    private static final int LINE_LENGTH = 64;
    private final int nlLength;
    private char[] buf = new char[64];

    public PemWriter(Writer out) {
        super(out);
        String nl = Strings.lineSeparator();
        if (nl != null) {
            this.nlLength = nl.length();
        } else {
            this.nlLength = 2;
        }

    }

    public int getOutputSize(PemObject obj) {
        int size = 2 * (obj.getType().length() + 10 + this.nlLength) + 6 + 4;
        if (!obj.getHeaders().isEmpty()) {
            PemHeader hdr;
            for(Iterator it = obj.getHeaders().iterator(); it.hasNext(); size += hdr.getName().length() + ": ".length() + hdr.getValue().length() + this.nlLength) {
                hdr = (PemHeader)it.next();
            }

            size += this.nlLength;
        }

        int dataLen = (obj.getContent().length + 2) / 3 * 4;
        size += dataLen + (dataLen + 64 - 1) / 64 * this.nlLength;
        return size;
    }

    public void writeObject(PemObjectGenerator objGen) throws IOException {
        PemObject obj = objGen.generate();
        this.writePreEncapsulationBoundary(obj.getType());
        if (!obj.getHeaders().isEmpty()) {
            Iterator it = obj.getHeaders().iterator();

            while(it.hasNext()) {
                PemHeader hdr = (PemHeader)it.next();
                this.write(hdr.getName());
                this.write(": ");
                this.write(hdr.getValue());
                this.newLine();
            }

            this.newLine();
        }

        this.writeEncoded(obj.getContent());
        this.writePostEncapsulationBoundary(obj.getType());
    }

    private void writeEncoded(byte[] bytes) throws IOException {
        bytes = Base64.encode(bytes);

        for(int i = 0; i < bytes.length; i += this.buf.length) {
            int index;
            for(index = 0; index != this.buf.length && i + index < bytes.length; ++index) {
                this.buf[index] = (char)bytes[i + index];
            }

            this.write(this.buf, 0, index);
            this.newLine();
        }

    }

    private void writePreEncapsulationBoundary(String type) throws IOException {
        this.write("-----BEGIN " + type + "-----");
        this.newLine();
    }

    private void writePostEncapsulationBoundary(String type) throws IOException {
        this.write("-----END " + type + "-----");
        this.newLine();
    }
}
