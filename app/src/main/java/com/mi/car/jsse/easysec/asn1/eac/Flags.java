package com.mi.car.jsse.easysec.asn1.eac;

import java.util.Enumeration;
import java.util.Hashtable;

public class Flags {
    int value = 0;

    public Flags() {
    }

    public Flags(int v) {
        this.value = v;
    }

    public void set(int flag) {
        this.value |= flag;
    }

    public boolean isSet(int flag) {
        return (this.value & flag) != 0;
    }

    public int getFlags() {
        return this.value;
    }

    /* access modifiers changed from: package-private */
    public String decode(Hashtable decodeMap) {
        StringJoiner joiner = new StringJoiner(" ");
        Enumeration e = decodeMap.keys();
        while (e.hasMoreElements()) {
            Integer i = (Integer) e.nextElement();
            if (isSet(i.intValue())) {
                joiner.add((String) decodeMap.get(i));
            }
        }
        return joiner.toString();
    }

    private static class StringJoiner {
        boolean First = true;
        StringBuffer b = new StringBuffer();
        String mSeparator;

        public StringJoiner(String separator) {
            this.mSeparator = separator;
        }

        public void add(String str) {
            if (this.First) {
                this.First = false;
            } else {
                this.b.append(this.mSeparator);
            }
            this.b.append(str);
        }

        public String toString() {
            return this.b.toString();
        }
    }
}
