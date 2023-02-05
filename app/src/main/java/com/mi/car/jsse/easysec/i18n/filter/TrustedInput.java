package com.mi.car.jsse.easysec.i18n.filter;

public class TrustedInput {
    protected Object input;

    public TrustedInput(Object input2) {
        this.input = input2;
    }

    public Object getInput() {
        return this.input;
    }

    public String toString() {
        return this.input.toString();
    }
}
