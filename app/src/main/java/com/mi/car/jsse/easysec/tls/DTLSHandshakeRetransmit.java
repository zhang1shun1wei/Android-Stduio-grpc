package com.mi.car.jsse.easysec.tls;

import java.io.IOException;

/* access modifiers changed from: package-private */
public interface DTLSHandshakeRetransmit {
    void receivedHandshakeRecord(int i, byte[] bArr, int i2, int i3) throws IOException;
}
