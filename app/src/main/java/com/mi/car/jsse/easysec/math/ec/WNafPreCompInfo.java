package com.mi.car.jsse.easysec.math.ec;

public class WNafPreCompInfo implements PreCompInfo {
    protected int confWidth = -1;
    protected ECPoint[] preComp = null;
    protected ECPoint[] preCompNeg = null;
    volatile int promotionCountdown = 4;
    protected ECPoint twice = null;
    protected int width = -1;

    /* access modifiers changed from: package-private */
    public int decrementPromotionCountdown() {
        int t = this.promotionCountdown;
        if (t <= 0) {
            return t;
        }
        int t2 = t - 1;
        this.promotionCountdown = t2;
        return t2;
    }

    /* access modifiers changed from: package-private */
    public int getPromotionCountdown() {
        return this.promotionCountdown;
    }

    /* access modifiers changed from: package-private */
    public void setPromotionCountdown(int promotionCountdown2) {
        this.promotionCountdown = promotionCountdown2;
    }

    public boolean isPromoted() {
        return this.promotionCountdown <= 0;
    }

    public int getConfWidth() {
        return this.confWidth;
    }

    public void setConfWidth(int confWidth2) {
        this.confWidth = confWidth2;
    }

    public ECPoint[] getPreComp() {
        return this.preComp;
    }

    public void setPreComp(ECPoint[] preComp2) {
        this.preComp = preComp2;
    }

    public ECPoint[] getPreCompNeg() {
        return this.preCompNeg;
    }

    public void setPreCompNeg(ECPoint[] preCompNeg2) {
        this.preCompNeg = preCompNeg2;
    }

    public ECPoint getTwice() {
        return this.twice;
    }

    public void setTwice(ECPoint twice2) {
        this.twice = twice2;
    }

    public int getWidth() {
        return this.width;
    }

    public void setWidth(int width2) {
        this.width = width2;
    }
}
