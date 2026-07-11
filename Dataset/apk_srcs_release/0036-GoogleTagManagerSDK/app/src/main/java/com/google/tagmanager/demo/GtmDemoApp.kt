package com.google.tagmanager.demo

import android.app.Application
import com.google.firebase.FirebaseApp

class GtmDemoApp : Application() {

    override fun onCreate() {
        super.onCreate()
        FirebaseApp.initializeApp(this)
    }
}
