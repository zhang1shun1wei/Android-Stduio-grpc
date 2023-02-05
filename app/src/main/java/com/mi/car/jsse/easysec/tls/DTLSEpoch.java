package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCipher;
import java.io.IOException;

/* access modifiers changed from: package-private */
public class DTLSEpoch {
    private final TlsCipher cipher;
    private final int epoch;
    private final DTLSReplayWindow replayWindow = new DTLSReplayWindow();
    private long sequenceNumber = 0;

    DTLSEpoch(int epoch2, TlsCipher cipher2) {
        if (epoch2 < 0) {
            throw new IllegalArgumentException("'epoch' must be >= 0");
        } else if (cipher2 == null) {
            throw new IllegalArgumentException("'cipher' cannot be null");
        } else {
            this.epoch = epoch2;
            this.cipher = cipher2;
        }
    }

    /* access modifiers changed from: package-private */
    public synchronized long allocateSequenceNumber() throws IOException {
        long j;
        if (this.sequenceNumber >= 281474976710656L) {
            throw new TlsFatalAlert((short) 80);
        }
        j = this.sequenceNumber;
        this.sequenceNumber = 1 + j;
        return j;
    }

    /* access modifiers changed from: package-private */
    public TlsCipher getCipher() {
        return this.cipher;
    }

    /* access modifiers changed from: package-private */
    public int getEpoch() {
        return this.epoch;
    }

    /* access modifiers changed from: package-private */
    public DTLSReplayWindow getReplayWindow() {
        return this.replayWindow;
    }

    /* access modifiers changed from: package-private */
    public synchronized long getSequenceNumber() {
        return this.sequenceNumber;
    }

    /* access modifiers changed from: package-private */
    public synchronized void setSequenceNumber(long sequenceNumber2) {
        this.sequenceNumber = sequenceNumber2;
    }
}
