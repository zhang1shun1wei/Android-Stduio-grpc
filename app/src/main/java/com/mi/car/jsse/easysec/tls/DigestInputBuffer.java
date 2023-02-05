package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/* access modifiers changed from: package-private */
public class DigestInputBuffer extends ByteArrayOutputStream {
    DigestInputBuffer() {
    }

    /* access modifiers changed from: package-private */
    public void updateDigest(TlsHash d) {
        d.update(this.buf, 0, this.count);
    }

    /* access modifiers changed from: package-private */
    public void copyInputTo(OutputStream output) throws IOException {
        Streams.pipeAll(new ByteArrayInputStream(this.buf, 0, this.count), output);
    }
}
