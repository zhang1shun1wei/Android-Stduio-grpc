package com.mi.car.jsse.easysec.i18n;

import java.io.UnsupportedEncodingException;
import java.util.Locale;
import java.util.TimeZone;

public class ErrorBundle extends MessageBundle {
    public static final String DETAIL_ENTRY = "details";
    public static final String SUMMARY_ENTRY = "summary";

    public ErrorBundle(String resource, String id) throws NullPointerException {
        super(resource, id);
    }

    public ErrorBundle(String resource, String id, String encoding) throws NullPointerException, UnsupportedEncodingException {
        super(resource, id, encoding);
    }

    public ErrorBundle(String resource, String id, Object[] arguments) throws NullPointerException {
        super(resource, id, arguments);
    }

    public ErrorBundle(String resource, String id, String encoding, Object[] arguments) throws NullPointerException, UnsupportedEncodingException {
        super(resource, id, encoding, arguments);
    }

    public String getSummary(Locale loc, TimeZone timezone) throws MissingEntryException {
        return getEntry(SUMMARY_ENTRY, loc, timezone);
    }

    public String getSummary(Locale loc) throws MissingEntryException {
        return getEntry(SUMMARY_ENTRY, loc, TimeZone.getDefault());
    }

    public String getDetail(Locale loc, TimeZone timezone) throws MissingEntryException {
        return getEntry(DETAIL_ENTRY, loc, timezone);
    }

    public String getDetail(Locale loc) throws MissingEntryException {
        return getEntry(DETAIL_ENTRY, loc, TimeZone.getDefault());
    }
}
