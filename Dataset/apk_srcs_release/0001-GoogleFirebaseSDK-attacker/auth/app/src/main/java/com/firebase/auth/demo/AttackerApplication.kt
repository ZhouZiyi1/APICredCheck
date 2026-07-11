package com.google.firebase.attacker

import android.app.Application
import android.util.Log

class AttackerApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            Log.e(
                TestSignals.TAG,
                "${TestSignals.UNCAUGHT_EXCEPTION}: thread=${thread.name}, error=${throwable.message}",
                throwable
            )
            previousHandler?.uncaughtException(thread, throwable)
        }
    }
}
