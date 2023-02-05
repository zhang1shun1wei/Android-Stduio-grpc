package com.mi.car.jsse.easysec.tls;

public final class RecordPreview {
    private final int contentLimit;
    private final int recordSize;

    static RecordPreview combineAppData(RecordPreview a, RecordPreview b) {
        return new RecordPreview(a.getRecordSize() + b.getRecordSize(), a.getContentLimit() + b.getContentLimit());
    }

    static RecordPreview extendRecordSize(RecordPreview a, int recordSize2) {
        return new RecordPreview(a.getRecordSize() + recordSize2, a.getContentLimit());
    }

    RecordPreview(int recordSize2, int contentLimit2) {
        this.recordSize = recordSize2;
        this.contentLimit = contentLimit2;
    }

    public int getApplicationDataLimit() {
        return this.contentLimit;
    }

    public int getContentLimit() {
        return this.contentLimit;
    }

    public int getRecordSize() {
        return this.recordSize;
    }
}
