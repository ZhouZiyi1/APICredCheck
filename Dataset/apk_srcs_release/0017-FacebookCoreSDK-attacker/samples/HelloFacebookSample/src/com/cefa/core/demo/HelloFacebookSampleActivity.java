/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.cefa.core.demo;

import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.fragment.app.FragmentActivity;
import com.facebook.*;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.facebook.Profile;
import com.facebook.login.widget.ProfilePictureView;
import com.facebook.share.Sharer;
import com.facebook.share.model.ShareLinkContent;
import com.facebook.share.model.SharePhoto;
import com.facebook.share.model.SharePhotoContent;
import com.facebook.share.widget.ShareDialog;

public class HelloFacebookSampleActivity extends FragmentActivity {

  private Button postStatusUpdateButton;
  private Button postPhotoButton;
  private ProfilePictureView profilePictureView;
  private TextView greeting;
  private TextView resultStatus;
  private CallbackManager callbackManager;
  private ProfileTracker profileTracker;
  private ShareDialog shareDialog;

  private FacebookCallback<Sharer.Result> shareCallback =
      new FacebookCallback<Sharer.Result>() {
        @Override
        public void onCancel() {
          Log.d("HelloFacebook", "Canceled");
          String result = "API returned cancellation: share dialog was canceled.";
          showPersistentResult(result);
          Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + result);
          Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
        }

        @Override
        public void onError(@NonNull FacebookException error) {
          Log.d("HelloFacebook", String.format("Error: %s", error.toString()));
          String message = error.getMessage();
          String result = "API returned failure: " + (message == null ? error.toString() : message);
          showPersistentResult(result);
          Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + result, error);
          Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
          showResult(getString(R.string.error), message);
        }

        @Override
        public void onSuccess(@NonNull Sharer.Result result) {
          Log.d("HelloFacebook", "Success!");
          if (result.getPostId() != null) {
            String title = getString(R.string.success);
            String id = result.getPostId();
            String alertMessage = getString(R.string.successfully_posted_post, id);
            String apiResult = "API returned: " + alertMessage;
            showPersistentResult(apiResult);
            Log.i(TestSignals.TAG, TestSignals.SDK_CALL_SUCCESS + ": " + apiResult);
            Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
            showResult(title, alertMessage);
          } else {
            String alertMessage = "Share completed without a post ID.";
            String apiResult = "API returned: " + alertMessage;
            showPersistentResult(apiResult);
            Log.i(TestSignals.TAG, TestSignals.SDK_CALL_SUCCESS + ": " + apiResult);
            Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
            showResult("Success", alertMessage);
          }
        }

        private void showResult(String title, String alertMessage) {
          new AlertDialog.Builder(HelloFacebookSampleActivity.this)
              .setTitle(title)
              .setMessage(alertMessage)
              .setPositiveButton(R.string.ok, null)
              .show();
        }
      };

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    callbackManager = CallbackManager.Factory.create();
    shareDialog = new ShareDialog(this);
    shareDialog.registerCallback(callbackManager, shareCallback);

    setContentView(R.layout.main);

    profileTracker =
        new ProfileTracker() {
          @Override
          protected void onCurrentProfileChanged(Profile oldProfile, Profile currentProfile) {
            updateUI();
          }
        };

    profilePictureView = (ProfilePictureView) findViewById(R.id.profilePicture);
    greeting = (TextView) findViewById(R.id.greeting);
    resultStatus = (TextView) findViewById(R.id.resultStatus);

    postStatusUpdateButton = (Button) findViewById(R.id.postStatusUpdateButton);
    postStatusUpdateButton.setOnClickListener(
        new View.OnClickListener() {
          public void onClick(View view) {
            shareLink();
          }
        });

    postPhotoButton = (Button) findViewById(R.id.postPhotoButton);
    postPhotoButton.setOnClickListener(
        new View.OnClickListener() {
          public void onClick(View view) {
            sharePhoto();
          }
        });

    Log.i(TestSignals.TAG, TestSignals.READY);
    postStatusUpdateButton.postDelayed(
        new Runnable() {
          @Override
          public void run() {
            Log.i(TestSignals.TAG, TestSignals.MAIN_AUTO_CLICK_SHARE_LINK);
            postStatusUpdateButton.performClick();
          }
        },
        2500L);
  }

  @Override
  protected void onResume() {
    super.onResume();
    updateUI();
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    callbackManager.onActivityResult(requestCode, resultCode, data);
  }

  @Override
  protected void onDestroy() {
    super.onDestroy();
    profileTracker.stopTracking();
  }

  private void updateUI() {
    boolean loggedIn = AccessToken.isCurrentAccessTokenActive();
    Profile profile = Profile.getCurrentProfile();
    
    if (loggedIn && profile != null) {
      profilePictureView.setProfileId(profile.getId());
      greeting.setText(getString(R.string.hello_user, profile.getFirstName()));
    } else {
      profilePictureView.setProfileId(null);
      greeting.setText(null);
    }
  }

  private void shareLink() {
    showPersistentResult("Calling Facebook Core API: ShareDialog.show(link)");
    Log.i(TestSignals.TAG, TestSignals.SDK_CALL_START);
    try {
      ShareLinkContent linkContent =
          new ShareLinkContent.Builder()
              .setContentUrl(Uri.parse("https://developers.facebook.com"))
              .build();
      if (ShareDialog.canShow(ShareLinkContent.class)) {
        shareDialog.show(linkContent);
        String result = "API returned: ShareDialog accepted ShareLinkContent.";
        showPersistentResult(result);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_SUCCESS + ": " + result);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
      } else {
        String result = "API returned failure: ShareDialog cannot show ShareLinkContent.";
        showPersistentResult(result);
        Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + result);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
      }
    } catch (RuntimeException exception) {
      String result = "API returned exception: " + exception;
      showPersistentResult(result);
      Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + result, exception);
      Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
    }
  }

  private void sharePhoto() {
    showPersistentResult("Calling Facebook Core API: ShareDialog.show(photo)");
    Log.i(TestSignals.TAG, TestSignals.SDK_CALL_START);
    try {
      Bitmap image = BitmapFactory.decodeResource(this.getResources(), R.drawable.icon);
      if (image == null) {
        String result = "API returned failure: photo bitmap decoded as null.";
        showPersistentResult(result);
        Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + result);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
        return;
      }
      SharePhoto sharePhoto = new SharePhoto.Builder().setBitmap(image).build();
      SharePhotoContent sharePhotoContent = new SharePhotoContent.Builder().addPhoto(sharePhoto).build();

      if (ShareDialog.canShow(SharePhotoContent.class)) {
        shareDialog.show(sharePhotoContent);
        String result = "API returned: ShareDialog accepted SharePhotoContent.";
        showPersistentResult(result);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_SUCCESS + ": " + result);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
      } else {
        String result = "API returned failure: ShareDialog cannot show SharePhotoContent.";
        showPersistentResult(result);
        Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + result);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
      }
    } catch (RuntimeException exception) {
      String result = "API returned exception: " + exception;
      showPersistentResult(result);
      Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + result, exception);
      Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
    }
  }

  private void showPersistentResult(String message) {
    if (resultStatus != null) {
      resultStatus.setText(message);
    }
  }
}
