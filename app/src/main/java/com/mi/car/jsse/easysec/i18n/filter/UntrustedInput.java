package com.mi.car.jsse.easysec.i18n.filter;

public class UntrustedInput {
    protected Object input;

    public UntrustedInput(Object input2) {
        this.input = input2;
    }

    public Object getInput() {
        return this.input;
    }

    public String getString() {
        return this.input.toString();
    }

    public String toString() {
        return this.input.toString();
    }
}
