/*
 * Copyright (C) 2019 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.usermessaging.attacker;

import android.os.Bundle;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Display;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.AdSize;
import com.google.android.gms.ads.AdView;
import com.google.android.gms.ads.LoadAdError;
import com.google.android.gms.ads.MobileAds;
import com.google.android.gms.ads.RequestConfiguration;
import com.google.android.gms.ads.initialization.InitializationStatus;
import com.google.android.gms.ads.initialization.OnInitializationCompleteListener;
import java.util.Arrays;

/** Main Activity. Inflates main activity xml and child fragments. */
public class MyActivity extends AppCompatActivity {

  // This is an ad unit ID for a test ad. Replace with your own banner ad unit ID.
  private static final String AD_UNIT_ID = "ca-app-pub-1111111111111111/1111111111";
  private FrameLayout adContainerView;
  private AdView adView;
  private Button loadAdButton;
  private TextView statusText;
  private boolean mobileAdsInitialized;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_my);

    adContainerView = findViewById(R.id.ad_view_container);
    loadAdButton = findViewById(R.id.load_ad_button);
    statusText = findViewById(R.id.status_text);

    loadAdButton.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View view) {
        callAdMobApi();
      }
    });

    Log.i(TestSignals.TAG, TestSignals.READY);
    loadAdButton.postDelayed(new Runnable() {
      @Override
      public void run() {
        Log.i(TestSignals.TAG, TestSignals.MAIN_AUTO_CLICK_LOAD_AD);
        loadAdButton.performClick();
      }
    }, 2500L);
  }

  /** Called when leaving the activity */
  @Override
  public void onPause() {
    if (adView != null) {
      adView.pause();
    }
    super.onPause();
  }

  /** Called when returning to the activity */
  @Override
  public void onResume() {
    super.onResume();
    if (adView != null) {
      adView.resume();
    }
  }

  /** Called before the activity is destroyed */
  @Override
  public void onDestroy() {
    destroyCurrentAd();
    super.onDestroy();
  }

  private void callAdMobApi() {
    loadAdButton.setEnabled(false);
    statusText.setText("Calling Google User Messaging Platform API...");
    Log.i(TestSignals.TAG, TestSignals.SDK_CALL_START);

    if (mobileAdsInitialized) {
      loadBannerWhenLayoutReady();
      return;
    }

    // Set your test devices only after the button is clicked, so startup remains controlled.
    MobileAds.setRequestConfiguration(
        new RequestConfiguration.Builder().setTestDeviceIds(Arrays.asList("ABCDEF012345")).build());

    MobileAds.initialize(this, new OnInitializationCompleteListener() {
      @Override
      public void onInitializationComplete(InitializationStatus initializationStatus) {
        mobileAdsInitialized = true;
        loadBannerWhenLayoutReady();
      }
    });
  }

  private void loadBannerWhenLayoutReady() {
    // Since we're loading the banner based on the adContainerView size, wait until this
    // view is laid out before reading the width.
    adContainerView.post(new Runnable() {
      @Override
      public void run() {
        loadBanner();
      }
    });
  }

  private void loadBanner() {
    destroyCurrentAd();

    adView = new AdView(this);
    adView.setAdUnitId(AD_UNIT_ID);
    adView.setAdListener(new AdListener() {
      @Override
      public void onAdLoaded() {
        statusText.setText("API returned: banner ad loaded for unit " + AD_UNIT_ID);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_SUCCESS);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
        loadAdButton.setEnabled(true);
      }

      @Override
      public void onAdFailedToLoad(LoadAdError loadAdError) {
        statusText.setText("API returned failure: " + loadAdError);
        Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + loadAdError);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
        destroyCurrentAd();
        loadAdButton.setEnabled(true);
      }
    });
    adContainerView.removeAllViews();
    adContainerView.addView(adView);

    AdSize adSize = getAdSize();
    adView.setAdSize(adSize);

    AdRequest adRequest = new AdRequest.Builder().build();

    // Start loading the ad in the background.
    try {
      adView.loadAd(adRequest);
    } catch (RuntimeException e) {
      statusText.setText("API threw exception: " + e.getMessage());
      Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE, e);
      Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
      destroyCurrentAd();
      loadAdButton.setEnabled(true);
    }
  }

  private void destroyCurrentAd() {
    if (adView != null) {
      adView.destroy();
      adView = null;
    }
    if (adContainerView != null) {
      adContainerView.removeAllViews();
    }
  }

  private AdSize getAdSize() {
    // Determine the screen width (less decorations) to use for the ad width.
    Display display = getWindowManager().getDefaultDisplay();
    DisplayMetrics outMetrics = new DisplayMetrics();
    display.getMetrics(outMetrics);

    float density = outMetrics.density;

    float adWidthPixels = adContainerView.getWidth();

    // If the ad hasn't been laid out, default to the full screen width.
    if (adWidthPixels == 0) {
      adWidthPixels = outMetrics.widthPixels;
    }

    int adWidth = (int) (adWidthPixels / density);

    return AdSize.getCurrentOrientationBannerAdSizeWithWidth(this, adWidth);
  }
}
