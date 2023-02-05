package com.mi.car.jsse.easysec.tls;

/* access modifiers changed from: package-private */
public class Timeout {
    private long durationMillis;
    private long startMillis;

    Timeout(long durationMillis2) {
        this(durationMillis2, System.currentTimeMillis());
    }

    Timeout(long durationMillis2, long currentTimeMillis) {
        this.durationMillis = Math.max(0L, durationMillis2);
        this.startMillis = Math.max(0L, currentTimeMillis);
    }

    /* access modifiers changed from: package-private */
    public synchronized long remainingMillis(long currentTimeMillis) {
        long remaining;
        if (this.startMillis > currentTimeMillis) {
            this.startMillis = currentTimeMillis;
            remaining = this.durationMillis;
        } else {
            remaining = this.durationMillis - (currentTimeMillis - this.startMillis);
            if (remaining <= 0) {
                this.durationMillis = 0;
                remaining = 0;
            }
        }
        return remaining;
    }

    static int constrainWaitMillis(int waitMillis, Timeout timeout, long currentTimeMillis) {
        if (waitMillis < 0) {
            return -1;
        }
        int timeoutMillis = getWaitMillis(timeout, currentTimeMillis);
        if (timeoutMillis < 0) {
            return -1;
        }
        if (waitMillis != 0) {
            return timeoutMillis == 0 ? waitMillis : Math.min(waitMillis, timeoutMillis);
        }
        return timeoutMillis;
    }

    static Timeout forWaitMillis(int waitMillis) {
        return forWaitMillis(waitMillis, System.currentTimeMillis());
    }

    static Timeout forWaitMillis(int waitMillis, long currentTimeMillis) {
        if (waitMillis < 0) {
            throw new IllegalArgumentException("'waitMillis' cannot be negative");
        } else if (waitMillis > 0) {
            return new Timeout((long) waitMillis, currentTimeMillis);
        } else {
            return null;
        }
    }

    static int getWaitMillis(Timeout timeout, long currentTimeMillis) {
        if (timeout == null) {
            return 0;
        }
        long remainingMillis = timeout.remainingMillis(currentTimeMillis);
        if (remainingMillis < 1) {
            return -1;
        }
        if (remainingMillis > 2147483647L) {
            return Integer.MAX_VALUE;
        }
        return (int) remainingMillis;
    }

    static boolean hasExpired(Timeout timeout, long currentTimeMillis) {
        return timeout != null && timeout.remainingMillis(currentTimeMillis) < 1;
    }
}
