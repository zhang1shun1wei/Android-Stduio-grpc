package com.mi.car.jsse.easysec.util;

public interface Selector<T> extends Cloneable {
    Object clone();
    boolean match(T t);
}
