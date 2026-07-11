/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.cefa.share.attacker;

import android.app.Application;
import android.util.Log;

public class APICredTestApplication extends Application {
  @Override
  public void onCreate() {
    super.onCreate();
    Thread.UncaughtExceptionHandler previousHandler = Thread.getDefaultUncaughtExceptionHandler();
    Thread.setDefaultUncaughtExceptionHandler(
        (thread, throwable) -> {
          Log.e(
              TestSignals.TAG,
              TestSignals.UNCAUGHT_EXCEPTION
                  + ": thread="
                  + thread.getName()
                  + ", error="
                  + throwable.getMessage(),
              throwable);
          if (previousHandler != null) {
            previousHandler.uncaughtException(thread, throwable);
          }
        });
  }
}
