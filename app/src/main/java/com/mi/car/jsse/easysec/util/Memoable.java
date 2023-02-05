package com.mi.car.jsse.easysec.util;

public interface Memoable {
    Memoable copy();

    void reset(Memoable memoable);
}
