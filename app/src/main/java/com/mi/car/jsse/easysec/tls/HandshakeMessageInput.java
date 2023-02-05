package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import java.io.ByteArrayInputStream;

public class HandshakeMessageInput extends ByteArrayInputStream {
    HandshakeMessageInput(byte[] buf, int offset, int length) {
        super(buf, offset, length);
    }

    public boolean markSupported() {
        return false;
    }

    public void mark(int readAheadLimit) {
        throw new UnsupportedOperationException();
    }

    public void updateHash(TlsHash hash) {
        hash.update(this.buf, this.mark, this.count - this.mark);
    }

    /* access modifiers changed from: package-private */
    public void updateHashPrefix(TlsHash hash, int bindersSize) {
        hash.update(this.buf, this.mark, (this.count - this.mark) - bindersSize);
    }

    /* access modifiers changed from: package-private */
    public void updateHashSuffix(TlsHash hash, int bindersSize) {
        hash.update(this.buf, this.count - bindersSize, bindersSize);
    }
}
