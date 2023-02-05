package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Pack;

public class DefaultTlsHeartbeat implements TlsHeartbeat {
    private int counter = 0;
    private final int idleMillis;
    private final int timeoutMillis;

    public DefaultTlsHeartbeat(int idleMillis2, int timeoutMillis2) {
        if (idleMillis2 <= 0) {
            throw new IllegalArgumentException("'idleMillis' must be > 0");
        } else if (timeoutMillis2 <= 0) {
            throw new IllegalArgumentException("'timeoutMillis' must be > 0");
        } else {
            this.idleMillis = idleMillis2;
            this.timeoutMillis = timeoutMillis2;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHeartbeat
    public synchronized byte[] generatePayload() {
        int i;
        i = this.counter + 1;
        this.counter = i;
        return Pack.intToBigEndian(i);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHeartbeat
    public int getIdleMillis() {
        return this.idleMillis;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsHeartbeat
    public int getTimeoutMillis() {
        return this.timeoutMillis;
    }
}
