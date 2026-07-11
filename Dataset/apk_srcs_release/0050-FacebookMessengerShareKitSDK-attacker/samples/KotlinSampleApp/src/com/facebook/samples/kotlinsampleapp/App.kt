/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.facebook.samples.kotlinsampleapp

import androidx.compose.foundation.layout.padding
import androidx.compose.material.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.facebook.samples.kotlinsampleapp.home.HomeScreen
import com.facebook.samples.kotlinsampleapp.home.HomeViewModel

enum class Screen {
  MainScreen
}

@Composable
fun App(homeViewModel: HomeViewModel) {
  val navController = rememberNavController()
  Scaffold() { innerPadding -> NavHost(navController, modifier = Modifier.padding(innerPadding)) }
}

@Composable
fun NavHost(navController: NavHostController, modifier: Modifier = Modifier) {
  NavHost(
      navController = navController,
      startDestination = Screen.MainScreen.name,
      modifier = modifier) {
        composable(Screen.MainScreen.name) {
          val homeViewModel: HomeViewModel = viewModel()
          HomeScreen(homeViewModel)
        }
      }
}
