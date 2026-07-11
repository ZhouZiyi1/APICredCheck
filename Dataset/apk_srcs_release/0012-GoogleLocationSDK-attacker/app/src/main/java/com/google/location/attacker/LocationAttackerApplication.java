package com.google.location.attacker;

import android.app.Application;
import android.util.Log;

public class LocationAttackerApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        Thread.UncaughtExceptionHandler previousHandler = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            Log.e(
                    TestSignals.TAG,
                    TestSignals.UNCAUGHT_EXCEPTION
                            + ": thread=" + thread.getName()
                            + ", error=" + throwable.getMessage(),
                    throwable
            );
            if (previousHandler != null) {
                previousHandler.uncaughtException(thread, throwable);
            }
        });
    }
}
