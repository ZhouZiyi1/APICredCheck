/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.facebook.samples.kotlinsampleapp.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.cefa.messenger.demo.R
import com.facebook.samples.kotlinsampleapp.common.MenuItem
import com.facebook.samples.kotlinsampleapp.sharing.shareLink
import com.facebook.samples.kotlinsampleapp.sharing.sharePhotos
import com.facebook.samples.kotlinsampleapp.sharing.shareVideo

@Composable
fun HomeScreen(homeViewModel: HomeViewModel) {
  val context = LocalContext.current
  val status = remember { mutableStateOf("Ready. Tap a sharing button.") }
  Column(verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(16.dp)) {
    Text("0050FacebookMessengerShareDemo")
    Text("This screen shows how to to share content using FB SDK")
    MenuItem(
        "Share link",
        onClick = {
          val launched = shareLink(context, "https://developers.facebook.com")
          status.value =
              if (launched) "Share link dialog launched."
              else "Share link failed: no Activity context."
        })
    MenuItem(
        "Share link with hashtag",
        onClick = {
          val launched =
              shareLink(context, "https://developers.facebook.com", hashtag = "#ConnectTheWorld")
          status.value =
              if (launched) "Share link with hashtag dialog launched."
              else "Share link with hashtag failed: no Activity context."
        })
    MenuItem(
        "Share link with quote",
        onClick = {
          val launched =
              shareLink(
                  context, "https://developers.facebook.com", quote = "Connect on a global scale.")
          status.value =
              if (launched) "Share link with quote dialog launched."
              else "Share link with quote failed: no Activity context."
        })
    MenuItem(
        "Share photos",
        onClick = {
          val launched =
              sharePhotos(
                  context,
                  listOf(
                      R.drawable.red,
                      R.drawable.black,
                      R.drawable.green,
                  ))
          status.value =
              if (launched) "Share photos dialog launched."
              else "Share photos failed: no Activity context."
        })
    MenuItem(
        "Share video",
        onClick = {
          val launched = shareVideo(context, R.raw.test)
          status.value =
              if (launched) "Share video dialog launched."
              else "Share video failed: no Activity context."
        })
    Text(status.value)
  }
}
