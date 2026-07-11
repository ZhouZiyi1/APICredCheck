/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.facebook.samples.kotlinsampleapp

import android.app.Application
import com.facebook.appevents.AppEventsLogger
import com.facebook.samples.kotlinsampleapp.home.TestSignals

class SampleApplication : Application() {
  override fun onCreate() {
    super.onCreate()
    val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
    Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
      TestSignals.logUncaughtException(thread, throwable)
      previousHandler?.uncaughtException(thread, throwable)
    }
    AppEventsLogger.activateApp(this)
  }
}
