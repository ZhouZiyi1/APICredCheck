package com.facebook.samples.kotlinsampleapp.home

import android.util.Log

object TestSignals {
  private const val TAG = "APICREDTEST"
  private const val READY = "APICREDTEST_READY"
  private const val MAIN_AUTO_CLICK_SHARE_LINK = "APICREDTEST_MAIN_AUTO_CLICK_SHARE_LINK"
  private const val SDK_CALL_START = "APICREDTEST_SDK_CALL_START"
  private const val SDK_CALL_SUCCESS = "APICREDTEST_SDK_CALL_SUCCESS"
  private const val SDK_CALL_FAILURE = "APICREDTEST_SDK_CALL_FAILURE"
  private const val SDK_CALL_COMPLETE = "APICREDTEST_SDK_CALL_COMPLETE"
  const val UNCAUGHT_EXCEPTION = "APICREDTEST_UNCAUGHT_EXCEPTION"
  const val MAIN_AUTO_CLICK_DELAY_MS = 2500L

  fun logReady() = Log.i(TAG, READY)

  fun logAutoClickShareLink() = Log.i(TAG, MAIN_AUTO_CLICK_SHARE_LINK)

  fun logStart() = Log.i(TAG, SDK_CALL_START)

  fun logSuccess(message: String) = Log.i(TAG, "$SDK_CALL_SUCCESS: $message")

  fun logFailure(message: String, throwable: Throwable? = null) {
    if (throwable != null) {
      Log.e(TAG, "$SDK_CALL_FAILURE: $message", throwable)
    } else {
      Log.e(TAG, "$SDK_CALL_FAILURE: $message")
    }
  }

  fun logComplete() = Log.i(TAG, SDK_CALL_COMPLETE)

  fun logUncaughtException(thread: Thread, throwable: Throwable) {
    Log.e(TAG, "$UNCAUGHT_EXCEPTION: thread=${thread.name}, error=${throwable.message}", throwable)
  }
}
