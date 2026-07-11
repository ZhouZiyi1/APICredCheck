package com.google.tagmanager.attacker

import android.app.Application
import android.util.Log
import com.google.firebase.FirebaseApp

class GtmDemoApp : Application() {

    override fun onCreate() {
        super.onCreate()
        installUncaughtExceptionSignal()
        FirebaseApp.initializeApp(this)
    }

    private fun installUncaughtExceptionSignal() {
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
