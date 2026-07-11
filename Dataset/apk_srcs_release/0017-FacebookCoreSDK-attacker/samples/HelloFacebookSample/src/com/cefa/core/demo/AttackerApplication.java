package com.cefa.core.demo;

import android.app.Application;
import android.util.Log;

public class AttackerApplication extends Application {
  @Override
  public void onCreate() {
    super.onCreate();
    final Thread.UncaughtExceptionHandler previousHandler =
        Thread.getDefaultUncaughtExceptionHandler();
    Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
      @Override
      public void uncaughtException(Thread thread, Throwable throwable) {
        Log.e(TestSignals.TAG, TestSignals.UNCAUGHT_EXCEPTION, throwable);
        if (previousHandler != null) {
          previousHandler.uncaughtException(thread, throwable);
        }
      }
    });
  }
}
