package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.io.OutputStream;

public class ASN1OutputStream {
    private OutputStream os;

    public static ASN1OutputStream create(OutputStream out) {
        return new ASN1OutputStream(out);
    }

    public static ASN1OutputStream create(OutputStream out, String encoding) {
        if (encoding.equals(ASN1Encoding.DER)) {
            return new DEROutputStream(out);
        }
        if (encoding.equals(ASN1Encoding.DL)) {
            return new DLOutputStream(out);
        }
        return new ASN1OutputStream(out);
    }

    ASN1OutputStream(OutputStream os2) {
        this.os = os2;
    }

    public void close() throws IOException {
        this.os.close();
    }

    public void flush() throws IOException {
        this.os.flush();
    }

    public final void writeObject(ASN1Encodable encodable) throws IOException {
        if (encodable == null) {
            throw new IOException("null object detected");
        }
        writePrimitive(encodable.toASN1Primitive(), true);
        flushInternal();
    }

    public final void writeObject(ASN1Primitive primitive) throws IOException {
        if (primitive == null) {
            throw new IOException("null object detected");
        }
        writePrimitive(primitive, true);
        flushInternal();
    }

    /* access modifiers changed from: package-private */
    public void flushInternal() throws IOException {
    }

    /* access modifiers changed from: package-private */
    public DEROutputStream getDERSubStream() {
        return new DEROutputStream(this.os);
    }

    /* access modifiers changed from: package-private */
    public DLOutputStream getDLSubStream() {
        return new DLOutputStream(this.os);
    }

    /* access modifiers changed from: package-private */
    public final void writeDL(int length) throws IOException {
        if (length < 128) {
            write(length);
            return;
        }
        byte[] stack = new byte[5];
        int pos = stack.length;
        do {
            pos--;
            stack[pos] = (byte) length;
            length >>>= 8;
        } while (length != 0);
        int count = stack.length - pos;
        int pos2 = pos - 1;
        stack[pos2] = (byte) (count | 128);
        write(stack, pos2, count + 1);
    }

    /* access modifiers changed from: package-private */
    public final void write(int b) throws IOException {
        this.os.write(b);
    }

    /* access modifiers changed from: package-private */
    public final void write(byte[] bytes, int off, int len) throws IOException {
        this.os.write(bytes, off, len);
    }

    /* access modifiers changed from: package-private */
    public void writeElements(ASN1Encodable[] elements) throws IOException {
        for (ASN1Encodable aSN1Encodable : elements) {
            aSN1Encodable.toASN1Primitive().encode(this, true);
        }
    }

    /* access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean withID, int identifier, byte contents) throws IOException {
        writeIdentifier(withID, identifier);
        writeDL(1);
        write(contents);
    }

    /* access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean withID, int identifier, byte[] contents) throws IOException {
        writeIdentifier(withID, identifier);
        writeDL(contents.length);
        write(contents, 0, contents.length);
    }

    /* access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean withID, int identifier, byte[] contents, int contentsOff, int contentsLen) throws IOException {
        writeIdentifier(withID, identifier);
        writeDL(contentsLen);
        write(contents, contentsOff, contentsLen);
    }

    /* access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean withID, int identifier, byte contentsPrefix, byte[] contents, int contentsOff, int contentsLen) throws IOException {
        writeIdentifier(withID, identifier);
        writeDL(contentsLen + 1);
        write(contentsPrefix);
        write(contents, contentsOff, contentsLen);
    }

    /* access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean withID, int identifier, byte[] contents, int contentsOff, int contentsLen, byte contentsSuffix) throws IOException {
        writeIdentifier(withID, identifier);
        writeDL(contentsLen + 1);
        write(contents, contentsOff, contentsLen);
        write(contentsSuffix);
    }

    /* access modifiers changed from: package-private */
    public final void writeEncodingDL(boolean withID, int flags, int tag, byte[] contents) throws IOException {
        writeIdentifier(withID, flags, tag);
        writeDL(contents.length);
        write(contents, 0, contents.length);
    }

    /* access modifiers changed from: package-private */
    public final void writeEncodingIL(boolean withID, int identifier, ASN1Encodable[] elements) throws IOException {
        writeIdentifier(withID, identifier);
        write(128);
        writeElements(elements);
        write(0);
        write(0);
    }

    /* access modifiers changed from: package-private */
    public final void writeIdentifier(boolean withID, int identifier) throws IOException {
        if (withID) {
            write(identifier);
        }
    }

    /* access modifiers changed from: package-private */
    public final void writeIdentifier(boolean withID, int flags, int tag) throws IOException {
        if (withID) {
            if (tag < 31) {
                write(flags | tag);
                return;
            }
            byte[] stack = new byte[6];
            int pos = stack.length - 1;
            stack[pos] = (byte) (tag & 127);
            while (tag > 127) {
                tag >>>= 7;
                pos--;
                stack[pos] = (byte) ((tag & 127) | 128);
            }
            int pos2 = pos - 1;
            stack[pos2] = (byte) (flags | 31);
            write(stack, pos2, stack.length - pos2);
        }
    }

    /* access modifiers changed from: package-private */
    public void writePrimitive(ASN1Primitive primitive, boolean withID) throws IOException {
        primitive.encode(this, withID);
    }

    /* access modifiers changed from: package-private */
    public void writePrimitives(ASN1Primitive[] primitives) throws IOException {
        for (ASN1Primitive aSN1Primitive : primitives) {
            aSN1Primitive.encode(this, true);
        }
    }

    static int getLengthOfDL(int dl) {
        if (dl < 128) {
            return 1;
        }
        int length = 2;
        while (true) {
            dl >>>= 8;
            if (dl == 0) {
                return length;
            }
            length++;
        }
    }

    static int getLengthOfEncodingDL(boolean withID, int contentsLength) {
        return (withID ? 1 : 0) + getLengthOfDL(contentsLength) + contentsLength;
    }

    static int getLengthOfIdentifier(int tag) {
        if (tag < 31) {
            return 1;
        }
        int length = 2;
        while (true) {
            tag >>>= 7;
            if (tag == 0) {
                return length;
            }
            length++;
        }
    }
}
