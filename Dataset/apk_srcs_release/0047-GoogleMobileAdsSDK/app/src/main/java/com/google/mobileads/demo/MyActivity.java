/*
 * Copyright 2013-2023 Google LLC
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

package com.google.mobileads.demo;

import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.PopupMenu;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.AdSize;
import com.google.android.gms.ads.AdView;
import com.google.android.gms.ads.LoadAdError;
import com.google.android.gms.ads.MobileAds;
import com.google.android.gms.ads.RequestConfiguration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

/** Main Activity. Inflates main activity xml and child fragments. */
public class MyActivity extends AppCompatActivity {

  // Check your logcat output for the test device hashed ID e.g.
  // "Use RequestConfiguration.Builder().setTestDeviceIds(Arrays.asList("ABCDEF012345"))
  // to get test ads on this device" or
  // "Use new ConsentDebugSettings.Builder().addTestDeviceHashedId("ABCDEF012345") to set this as
  // a debug device".
  public static final String TEST_DEVICE_HASHED_ID = "ABCDEF012345";

  private static final String TAG = "MyActivity";
  private final AtomicBoolean isMobileAdsInitializeCalled = new AtomicBoolean(false);
  private GoogleMobileAdsConsentManager googleMobileAdsConsentManager;
  private AdView adView;
  private FrameLayout adContainerView;
  private TextView bannerStatusText;
  private boolean isMobileAdsInitialized;
  private boolean shouldLoadBannerAfterInitialize;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_my);
    setSupportActionBar(findViewById(R.id.toolBar));
    adContainerView = findViewById(R.id.ad_view_container);
    bannerStatusText = findViewById(R.id.banner_status);
    configureBannerControls();

    ViewCompat.setOnApplyWindowInsetsListener(
        findViewById(R.id.main),
        (view, insets) -> {
          Insets systemBarsInsets = insets.getInsets(WindowInsetsCompat.Type.systemBars());
          view.setPadding(
              systemBarsInsets.left, 0, systemBarsInsets.right, systemBarsInsets.bottom);
          return insets;
        });

    // Log the Mobile Ads SDK version.
    Log.d(TAG, "Google Mobile Ads SDK Version: " + MobileAds.getVersion());

    googleMobileAdsConsentManager =
        GoogleMobileAdsConsentManager.getInstance(getApplicationContext());
    googleMobileAdsConsentManager.gatherConsent(
        this,
        consentError -> {
          if (consentError != null) {
            // Consent not obtained in current session.
            Log.w(
                TAG,
                String.format("%s: %s", consentError.getErrorCode(), consentError.getMessage()));
          }

          if (googleMobileAdsConsentManager.canRequestAds()) {
            initializeMobileAdsSdk();
          } else {
            setBannerStatus("Consent is required before ads can be requested.");
          }

          if (googleMobileAdsConsentManager.isPrivacyOptionsRequired()) {
            // Regenerate the options menu to include a privacy setting.
            invalidateOptionsMenu();
          }
        });

    // This sample attempts to load ads using consent obtained in the previous session.
    if (googleMobileAdsConsentManager.canRequestAds()) {
      initializeMobileAdsSdk();
    }
  }

  private void configureBannerControls() {
    Button loadBannerButton = findViewById(R.id.load_banner_button);
    Button showBannerButton = findViewById(R.id.show_banner_button);
    Button hideBannerButton = findViewById(R.id.hide_banner_button);
    Button pauseBannerButton = findViewById(R.id.pause_banner_button);
    Button resumeBannerButton = findViewById(R.id.resume_banner_button);
    Button destroyBannerButton = findViewById(R.id.destroy_banner_button);

    loadBannerButton.setOnClickListener(
        view -> {
          if (!googleMobileAdsConsentManager.canRequestAds()) {
            setBannerStatus("Cannot request ads yet. Check consent/network status.");
            return;
          }
          if (isMobileAdsInitialized) {
            loadBanner();
          } else {
            shouldLoadBannerAfterInitialize = true;
            setBannerStatus("Initializing Google Mobile Ads SDK...");
            initializeMobileAdsSdk();
          }
        });
    showBannerButton.setOnClickListener(
        view -> {
          adContainerView.setVisibility(View.VISIBLE);
          setBannerStatus("Banner container is visible.");
        });
    hideBannerButton.setOnClickListener(
        view -> {
          adContainerView.setVisibility(View.GONE);
          setBannerStatus("Banner container is hidden.");
        });
    pauseBannerButton.setOnClickListener(
        view -> {
          if (adView != null) {
            adView.pause();
            setBannerStatus("Banner is paused.");
          } else {
            setBannerStatus("No banner to pause.");
          }
        });
    resumeBannerButton.setOnClickListener(
        view -> {
          if (adView != null) {
            adView.resume();
            setBannerStatus("Banner is resumed.");
          } else {
            setBannerStatus("No banner to resume.");
          }
        });
    destroyBannerButton.setOnClickListener(view -> destroyBanner("Banner destroyed."));
  }

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {
    getMenuInflater().inflate(R.menu.action_menu, menu);
    return true;
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    View menuItemView = findViewById(item.getItemId());
    PopupMenu popup = new PopupMenu(this, menuItemView);
    popup.getMenuInflater().inflate(R.menu.popup_menu, popup.getMenu());
    popup
        .getMenu()
        .findItem(R.id.privacy_settings)
        .setVisible(googleMobileAdsConsentManager.isPrivacyOptionsRequired());
    popup.show();
    popup.setOnMenuItemClickListener(
        popupMenuItem -> {
          if (popupMenuItem.getItemId() == R.id.privacy_settings) {
            // Handle changes to user consent.
            googleMobileAdsConsentManager.showPrivacyOptionsForm(
                this,
                formError -> {
                  if (formError != null) {
                    Toast.makeText(this, formError.getMessage(), Toast.LENGTH_SHORT).show();
                  }
                });
            return true;
          } else if (popupMenuItem.getItemId() == R.id.ad_inspector) {
            MobileAds.openAdInspector(
                this,
                error -> {
                  // Error will be non-null if ad inspector closed due to an error.
                  if (error != null) {
                    Toast.makeText(this, error.getMessage(), Toast.LENGTH_SHORT).show();
                  }
                });
            return true;
          }
          return false;
        });
    return super.onOptionsItemSelected(item);
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
    destroyBanner(null);
    super.onDestroy();
  }

  private void loadBanner() {
    destroyBanner(null);
    adContainerView.setVisibility(View.VISIBLE);

    // [START create_ad_view]
    // Create a new ad view.
    adView = new AdView(this);
    adView.setAdUnitId(getString(R.string.banner_ad_unit_id));
    // [START set_ad_size]
    adView.setAdSize(getAdSize());
    // [END set_ad_size]
    adView.setAdListener(
        new AdListener() {
          @Override
          public void onAdLoaded() {
            setBannerStatus("Banner loaded.");
          }

          @Override
          public void onAdFailedToLoad(LoadAdError adError) {
            setBannerStatus("Banner failed to load: " + adError.getMessage());
          }

          @Override
          public void onAdOpened() {
            setBannerStatus("Banner opened.");
          }

          @Override
          public void onAdClosed() {
            setBannerStatus("Banner closed.");
          }
        });

    // Replace ad container with new ad view.
    adContainerView.removeAllViews();
    adContainerView.addView(adView);
    // [END create_ad_view]

    // [START load_ad]
    AdRequest adRequest = new AdRequest.Builder().build();
    setBannerStatus("Loading banner...");
    adView.loadAd(adRequest);
    // [END load_ad]
  }

  private AdSize getAdSize() {
    float density = getResources().getDisplayMetrics().density;
    int adWidthPixels = adContainerView.getWidth();
    if (adWidthPixels == 0) {
      adWidthPixels = getResources().getDisplayMetrics().widthPixels;
    }
    int adWidth = (int) (adWidthPixels / density);
    return AdSize.getCurrentOrientationAnchoredAdaptiveBannerAdSize(this, adWidth);
  }

  private void destroyBanner(String statusMessage) {
    if (adView != null) {
      adView.destroy();
      adView = null;
    }
    if (adContainerView != null) {
      adContainerView.removeAllViews();
    }
    if (statusMessage != null) {
      setBannerStatus(statusMessage);
    }
  }

  private void initializeMobileAdsSdk() {
    if (isMobileAdsInitializeCalled.getAndSet(true)) {
      if (isMobileAdsInitialized && shouldLoadBannerAfterInitialize) {
        shouldLoadBannerAfterInitialize = false;
        loadBanner();
      }
      return;
    }

    // Set your test devices.
    MobileAds.setRequestConfiguration(
        new RequestConfiguration.Builder()
            .setTestDeviceIds(Arrays.asList(TEST_DEVICE_HASHED_ID))
            .build());

    // [START initialize_sdk]
    new Thread(
            () -> {
              // Initialize the Google Mobile Ads SDK on a background thread.
              MobileAds.initialize(this, initializationStatus -> {});
              // [START_EXCLUDE silent]
              runOnUiThread(
                  () -> {
                    isMobileAdsInitialized = true;
                    setBannerStatus("SDK initialized. Tap Load Banner.");
                    if (shouldLoadBannerAfterInitialize) {
                      shouldLoadBannerAfterInitialize = false;
                      loadBanner();
                    }
                  });
              // [END_EXCLUDE]
            })
        .start();
    // [END initialize_sdk]
  }

  private void setBannerStatus(String status) {
    if (bannerStatusText != null) {
      bannerStatusText.setText(status);
    }
    Log.d(TAG, status);
  }
}
