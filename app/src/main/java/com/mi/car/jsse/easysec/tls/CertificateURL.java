package com.mi.car.jsse.easysec.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

public class CertificateURL {
    protected short type;
    protected Vector urlAndHashList;

    public CertificateURL(short type2, Vector urlAndHashList2) {
        if (!CertChainType.isValid(type2)) {
            throw new IllegalArgumentException("'type' is not a valid CertChainType value");
        } else if (urlAndHashList2 == null || urlAndHashList2.isEmpty()) {
            throw new IllegalArgumentException("'urlAndHashList' must have length > 0");
        } else if (type2 != 1 || urlAndHashList2.size() == 1) {
            this.type = type2;
            this.urlAndHashList = urlAndHashList2;
        } else {
            throw new IllegalArgumentException("'urlAndHashList' must contain exactly one entry when type is " + CertChainType.getText(type2));
        }
    }

    public short getType() {
        return this.type;
    }

    public Vector getURLAndHashList() {
        return this.urlAndHashList;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint8(this.type, output);
        ListBuffer16 buf = new ListBuffer16();
        for (int i = 0; i < this.urlAndHashList.size(); i++) {
            ((URLAndHash) this.urlAndHashList.elementAt(i)).encode(buf);
        }
        buf.encodeTo(output);
    }

    public static CertificateURL parse(TlsContext context, InputStream input) throws IOException {
        short type2 = TlsUtils.readUint8(input);
        if (!CertChainType.isValid(type2)) {
            throw new TlsFatalAlert((short) 50);
        }
        int totalLength = TlsUtils.readUint16(input);
        if (totalLength < 1) {
            throw new TlsFatalAlert((short) 50);
        }
        ByteArrayInputStream buf = new ByteArrayInputStream(TlsUtils.readFully(totalLength, input));
        Vector url_and_hash_list = new Vector();
        while (buf.available() > 0) {
            url_and_hash_list.addElement(URLAndHash.parse(context, buf));
        }
        if (type2 != 1 || url_and_hash_list.size() == 1) {
            return new CertificateURL(type2, url_and_hash_list);
        }
        throw new TlsFatalAlert((short) 50);
    }

    class ListBuffer16 extends ByteArrayOutputStream {
        ListBuffer16() throws IOException {
            TlsUtils.writeUint16(0, this);
        }

        /* access modifiers changed from: package-private */
        public void encodeTo(OutputStream output) throws IOException {
            int length = this.count - 2;
            TlsUtils.checkUint16(length);
            TlsUtils.writeUint16(length, this.buf, 0);
            output.write(this.buf, 0, this.count);
            this.buf = null;
        }
    }
}
