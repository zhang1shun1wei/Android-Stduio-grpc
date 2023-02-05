package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.util.Memoable;

public final class Zuc256Engine extends Zuc256CoreEngine {
    public Zuc256Engine() {
    }

    public Zuc256Engine(int pLength) {
        super(pLength);
    }

    private Zuc256Engine(Zuc256Engine pSource) {
        super(pSource);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable, com.mi.car.jsse.easysec.crypto.engines.Zuc128CoreEngine, com.mi.car.jsse.easysec.crypto.engines.Zuc256CoreEngine
    public Memoable copy() {
        return new Zuc256Engine(this);
    }
}
