package com.onesignal.attacker.test

import android.util.Log

object TestSignals {
    const val TAG = "APICREDTEST"
    const val READY = "APICREDTEST_READY"
    const val MAIN_AUTO_CLICK_PUSH_SIMPLE = "APICREDTEST_MAIN_AUTO_CLICK_PUSH_SIMPLE"
    const val SDK_CALL_START = "APICREDTEST_SDK_CALL_START"
    const val SDK_CALL_SUCCESS = "APICREDTEST_SDK_CALL_SUCCESS"
    const val SDK_CALL_FAILURE = "APICREDTEST_SDK_CALL_FAILURE"
    const val SDK_CALL_COMPLETE = "APICREDTEST_SDK_CALL_COMPLETE"
    const val UNCAUGHT_EXCEPTION = "APICREDTEST_UNCAUGHT_EXCEPTION"

    fun info(message: String) {
        Log.i(TAG, message)
    }

    fun error(message: String, throwable: Throwable? = null) {
        if (throwable == null) {
            Log.e(TAG, message)
        } else {
            Log.e(TAG, message, throwable)
        }
    }
}
