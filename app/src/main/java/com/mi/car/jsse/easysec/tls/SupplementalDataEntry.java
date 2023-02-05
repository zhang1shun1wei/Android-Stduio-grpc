package com.mi.car.jsse.easysec.tls;

public class SupplementalDataEntry {
    protected byte[] data;
    protected int dataType;

    public SupplementalDataEntry(int dataType2, byte[] data2) {
        this.dataType = dataType2;
        this.data = data2;
    }

    public int getDataType() {
        return this.dataType;
    }

    public byte[] getData() {
        return this.data;
    }
}
