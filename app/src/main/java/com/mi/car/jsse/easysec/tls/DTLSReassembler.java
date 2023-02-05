package com.mi.car.jsse.easysec.tls;

import java.util.Vector;

/* access modifiers changed from: package-private */
public class DTLSReassembler {
    private byte[] body;
    private Vector missing = new Vector();
    private short msg_type;

    DTLSReassembler(short msg_type2, int length) {
        this.msg_type = msg_type2;
        this.body = new byte[length];
        this.missing.addElement(new Range(0, length));
    }

    /* access modifiers changed from: package-private */
    public short getMsgType() {
        return this.msg_type;
    }

    /* access modifiers changed from: package-private */
    public byte[] getBodyIfComplete() {
        if (this.missing.isEmpty()) {
            return this.body;
        }
        return null;
    }

    /* access modifiers changed from: package-private */
    public void contributeFragment(short msg_type2, int length, byte[] buf, int off, int fragment_offset, int fragment_length) {
        int fragment_end = fragment_offset + fragment_length;
        if (this.msg_type != msg_type2 || this.body.length != length || fragment_end > length) {
            return;
        }
        if (fragment_length != 0) {
            int i = 0;
            while (i < this.missing.size()) {
                Range range = (Range) this.missing.elementAt(i);
                if (range.getStart() < fragment_end) {
                    if (range.getEnd() > fragment_offset) {
                        int copyStart = Math.max(range.getStart(), fragment_offset);
                        int copyEnd = Math.min(range.getEnd(), fragment_end);
                        System.arraycopy(buf, (off + copyStart) - fragment_offset, this.body, copyStart, copyEnd - copyStart);
                        if (copyStart != range.getStart()) {
                            if (copyEnd != range.getEnd()) {
                                i++;
                                this.missing.insertElementAt(new Range(copyEnd, range.getEnd()), i);
                            }
                            range.setEnd(copyStart);
                        } else if (copyEnd == range.getEnd()) {
                            this.missing.removeElementAt(i);
                            i--;
                        } else {
                            range.setStart(copyEnd);
                        }
                    }
                    i++;
                } else {
                    return;
                }
            }
        } else if (fragment_offset == 0 && !this.missing.isEmpty() && ((Range) this.missing.firstElement()).getEnd() == 0) {
            this.missing.removeElementAt(0);
        }
    }

    /* access modifiers changed from: package-private */
    public void reset() {
        this.missing.removeAllElements();
        this.missing.addElement(new Range(0, this.body.length));
    }

    /* access modifiers changed from: private */
    public static class Range {
        private int end;
        private int start;

        Range(int start2, int end2) {
            this.start = start2;
            this.end = end2;
        }

        public int getStart() {
            return this.start;
        }

        public void setStart(int start2) {
            this.start = start2;
        }

        public int getEnd() {
            return this.end;
        }

        public void setEnd(int end2) {
            this.end = end2;
        }
    }
}
