package com.mi.car.jsse.easysec.tls;

public class TlsFatalAlert extends TlsException {
    protected short alertDescription;

    private static String getMessage(short alertDescription2, String detailMessage) {
        String msg = AlertDescription.getText(alertDescription2);
        if (detailMessage != null) {
            return msg + "; " + detailMessage;
        }
        return msg;
    }

    public TlsFatalAlert(short alertDescription2) {
        this(alertDescription2, (String) null);
    }

    public TlsFatalAlert(short alertDescription2, String detailMessage) {
        this(alertDescription2, detailMessage, null);
    }

    public TlsFatalAlert(short alertDescription2, Throwable alertCause) {
        this(alertDescription2, null, alertCause);
    }

    public TlsFatalAlert(short alertDescription2, String detailMessage, Throwable alertCause) {
        super(getMessage(alertDescription2, detailMessage), alertCause);
        this.alertDescription = alertDescription2;
    }

    public short getAlertDescription() {
        return this.alertDescription;
    }
}
