package com.mi.car.jsse.easysec.tls;

public class TlsFatalAlertReceived extends TlsException {
    protected short alertDescription;

    public TlsFatalAlertReceived(short alertDescription2) {
        super(AlertDescription.getText(alertDescription2));
        this.alertDescription = alertDescription2;
    }

    public short getAlertDescription() {
        return this.alertDescription;
    }
}
