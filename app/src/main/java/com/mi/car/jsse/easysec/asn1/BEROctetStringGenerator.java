package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.io.OutputStream;

public class BEROctetStringGenerator extends BERGenerator {
    public BEROctetStringGenerator(OutputStream out) throws IOException {
        super(out);
        writeBERHeader(36);
    }

    public BEROctetStringGenerator(OutputStream out, int tagNo, boolean isExplicit) throws IOException {
        super(out, tagNo, isExplicit);
        writeBERHeader(36);
    }

    public OutputStream getOctetOutputStream() {
        return getOctetOutputStream(new byte[1000]);
    }

    public OutputStream getOctetOutputStream(byte[] buf) {
        return new BufferedBEROctetStream(buf);
    }

    /* access modifiers changed from: private */
    public class BufferedBEROctetStream extends OutputStream {
        private byte[] _buf;
        private DEROutputStream _derOut;
        private int _off = 0;

        BufferedBEROctetStream(byte[] buf) {
            this._buf = buf;
            this._derOut = new DEROutputStream(BEROctetStringGenerator.this._out);
        }

        @Override // java.io.OutputStream
        public void write(int b) throws IOException {
            byte[] bArr = this._buf;
            int i = this._off;
            this._off = i + 1;
            bArr[i] = (byte) b;
            if (this._off == this._buf.length) {
                DEROctetString.encode(this._derOut, true, this._buf, 0, this._buf.length);
                this._off = 0;
            }
        }

        @Override // java.io.OutputStream
        public void write(byte[] b, int off, int len) throws IOException {
            int bufLen = this._buf.length;
            int available = bufLen - this._off;
            if (len < available) {
                System.arraycopy(b, off, this._buf, this._off, len);
                this._off += len;
                return;
            }
            int count = 0;
            if (this._off > 0) {
                System.arraycopy(b, off, this._buf, this._off, available);
                count = 0 + available;
                DEROctetString.encode(this._derOut, true, this._buf, 0, bufLen);
            }
            while (true) {
                int remaining = len - count;
                if (remaining >= bufLen) {
                    DEROctetString.encode(this._derOut, true, b, off + count, bufLen);
                    count += bufLen;
                } else {
                    System.arraycopy(b, off + count, this._buf, 0, remaining);
                    this._off = remaining;
                    return;
                }
            }
        }

        @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            if (this._off != 0) {
                DEROctetString.encode(this._derOut, true, this._buf, 0, this._off);
            }
            this._derOut.flushInternal();
            BEROctetStringGenerator.this.writeBEREnd();
        }
    }
}
