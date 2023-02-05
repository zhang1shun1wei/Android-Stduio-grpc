package com.mi.car.jsse.easysec.jsse;

import java.util.List;

public interface BCApplicationProtocolSelector<T> {
    String select(T t, List<String> list);
}
