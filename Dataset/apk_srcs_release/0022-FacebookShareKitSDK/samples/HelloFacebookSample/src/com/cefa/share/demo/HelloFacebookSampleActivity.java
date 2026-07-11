/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.cefa.share.demo;

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
  private TextView apiResult;
  private CallbackManager callbackManager;
  private ProfileTracker profileTracker;
  private ShareDialog shareDialog;

  private FacebookCallback<Sharer.Result> shareCallback =
      new FacebookCallback<Sharer.Result>() {
        @Override
        public void onCancel() {
          Log.d("HelloFacebook", "Canceled");
          setApiResult("API returned: cancelled");
        }

        @Override
        public void onError(@NonNull FacebookException error) {
          Log.d("HelloFacebook", String.format("Error: %s", error.toString()));
          String message = "API returned error: " + error.getMessage();
          setApiResult(message);
          showResult(getString(R.string.error), message);
        }

        @Override
        public void onSuccess(@NonNull Sharer.Result result) {
          Log.d("HelloFacebook", "Success!");
          if (result.getPostId() != null) {
            String title = getString(R.string.success);
            String id = result.getPostId();
            String alertMessage = getString(R.string.successfully_posted_post, id);
            setApiResult("API returned: postId=" + id);
            showResult(title, alertMessage);
          } else {
            String message = "API returned: share success with no postId";
            setApiResult(message);
            showResult("Success", message);
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
    apiResult = (TextView) findViewById(R.id.apiResult);
    setApiResult("API result: ready");

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
    setApiResult("API call started: ShareDialog.show(ShareLinkContent)");
    try {
      ShareLinkContent linkContent =
          new ShareLinkContent.Builder()
              .setContentUrl(Uri.parse("https://developers.facebook.com"))
              .build();
      if (ShareDialog.canShow(ShareLinkContent.class)) {
        shareDialog.show(linkContent);
      } else {
        setApiResult("API returned: ShareDialog cannot show ShareLinkContent");
      }
    } catch (Exception exception) {
      setApiResult("API threw exception: " + exception.getMessage());
    }
  }

  private void sharePhoto() {
    setApiResult("API call started: ShareDialog.show(SharePhotoContent)");
    try {
      Bitmap image = BitmapFactory.decodeResource(this.getResources(), R.drawable.icon);
      if (image == null) {
        setApiResult("API returned: null bitmap");
        return;
      }
      SharePhoto sharePhoto = new SharePhoto.Builder().setBitmap(image).build();
      SharePhotoContent sharePhotoContent =
          new SharePhotoContent.Builder().addPhoto(sharePhoto).build();

      if (ShareDialog.canShow(SharePhotoContent.class)) {
        shareDialog.show(sharePhotoContent);
      } else {
        setApiResult("API returned: ShareDialog cannot show SharePhotoContent");
      }
    } catch (Exception exception) {
      setApiResult("API threw exception: " + exception.getMessage());
    }
  }

  private void setApiResult(String message) {
    if (apiResult != null) {
      apiResult.setText(message);
    }
  }
}
