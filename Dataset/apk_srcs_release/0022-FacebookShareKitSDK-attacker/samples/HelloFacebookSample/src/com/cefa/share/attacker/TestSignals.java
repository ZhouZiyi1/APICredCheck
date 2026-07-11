/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.cefa.share.attacker;

final class TestSignals {
  static final String TAG = "APICREDTEST";
  static final String READY = "APICREDTEST_READY";
  static final String MAIN_AUTO_CLICK_SHARE_LINK = "APICREDTEST_MAIN_AUTO_CLICK_SHARE_LINK";
  static final String SDK_CALL_START = "APICREDTEST_SDK_CALL_START";
  static final String SDK_CALL_SUCCESS = "APICREDTEST_SDK_CALL_SUCCESS";
  static final String SDK_CALL_FAILURE = "APICREDTEST_SDK_CALL_FAILURE";
  static final String SDK_CALL_COMPLETE = "APICREDTEST_SDK_CALL_COMPLETE";
  static final String UNCAUGHT_EXCEPTION = "APICREDTEST_UNCAUGHT_EXCEPTION";
  static final long MAIN_AUTO_CLICK_DELAY_MS = 2500L;

  private TestSignals() {}
}
