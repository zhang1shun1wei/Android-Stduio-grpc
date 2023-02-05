package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.oer.OERDefinition;

public class DeferredElementSupplier implements ElementSupplier {
    private Element buildProduct;
    private final OERDefinition.Builder src;

    public DeferredElementSupplier(OERDefinition.Builder src2) {
        this.src = src2;
    }

    @Override // com.mi.car.jsse.easysec.oer.ElementSupplier
    public Element build() {
        Element element;
        synchronized (this) {
            if (this.buildProduct == null) {
                this.buildProduct = this.src.build();
            }
            element = this.buildProduct;
        }
        return element;
    }
}
