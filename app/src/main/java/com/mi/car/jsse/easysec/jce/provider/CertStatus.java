package com.mi.car.jsse.easysec.jce.provider;

import java.util.Date;

class CertStatus {
    public static final int UNDETERMINED = 12;
    public static final int UNREVOKED = 11;
    int certStatus = 11;
    Date revocationDate = null;

    CertStatus() {
    }

    public Date getRevocationDate() {
        return this.revocationDate;
    }

    public void setRevocationDate(Date revocationDate2) {
        this.revocationDate = revocationDate2;
    }

    public int getCertStatus() {
        return this.certStatus;
    }

    public void setCertStatus(int certStatus2) {
        this.certStatus = certStatus2;
    }
}
