package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;

/* access modifiers changed from: package-private */
public class TlsSessionImpl implements TlsSession {
    boolean resumable;
    final byte[] sessionID;
    final SessionParameters sessionParameters;

    TlsSessionImpl(byte[] sessionID2, SessionParameters sessionParameters2) {
        if (sessionID2 == null) {
            throw new IllegalArgumentException("'sessionID' cannot be null");
        } else if (sessionID2.length > 32) {
            throw new IllegalArgumentException("'sessionID' cannot be longer than 32 bytes");
        } else {
            this.sessionID = Arrays.clone(sessionID2);
            this.sessionParameters = sessionParameters2;
            this.resumable = sessionID2.length > 0 && sessionParameters2 != null;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsSession
    public synchronized SessionParameters exportSessionParameters() {
        return this.sessionParameters == null ? null : this.sessionParameters.copy();
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsSession
    public synchronized byte[] getSessionID() {
        return this.sessionID;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsSession
    public synchronized void invalidate() {
        this.resumable = false;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsSession
    public synchronized boolean isResumable() {
        return this.resumable;
    }
}
