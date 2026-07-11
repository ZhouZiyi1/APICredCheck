package com.google.location.attacker;

public final class TestSignals {
    public static final String TAG = "APICREDTEST";
    public static final String READY = "APICREDTEST_READY";
    public static final String MAIN_AUTO_CLICK_GET_LOCATION = "APICREDTEST_MAIN_AUTO_CLICK_GET_LOCATION";
    public static final String SDK_CALL_START = "APICREDTEST_SDK_CALL_START";
    public static final String SDK_CALL_SUCCESS = "APICREDTEST_SDK_CALL_SUCCESS";
    public static final String SDK_CALL_FAILURE = "APICREDTEST_SDK_CALL_FAILURE";
    public static final String SDK_CALL_COMPLETE = "APICREDTEST_SDK_CALL_COMPLETE";
    public static final String MAP_INIT_START = "APICREDTEST_MAP_INIT_START";
    public static final String MAP_READY = "APICREDTEST_MAP_READY";
    public static final String MAP_LOADED = "APICREDTEST_MAP_LOADED";
    public static final String MAP_LOAD_TIMEOUT = "APICREDTEST_MAP_LOAD_TIMEOUT";
    public static final String UNCAUGHT_EXCEPTION = "APICREDTEST_UNCAUGHT_EXCEPTION";

    public static final long MAIN_AUTO_CLICK_DELAY_MS = 2500L;
    public static final long MAP_INIT_DELAY_MS = 2500L;
    public static final long MAP_LOAD_TIMEOUT_MS = 15000L;

    private TestSignals() {
    }
}
