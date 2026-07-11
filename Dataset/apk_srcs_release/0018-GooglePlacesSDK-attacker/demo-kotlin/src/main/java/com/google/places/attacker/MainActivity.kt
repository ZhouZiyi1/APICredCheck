/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.places.attacker

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Button
import com.google.places.attacker.databinding.ActivityMainBinding
import com.google.places.attacker.programmatic_autocomplete.ProgrammaticAutocompleteGeocodingActivity

class MainActivity : BaseActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.topBar)
        binding.topBar.setNavigationIcon(R.drawable.ic_exit)
        binding.topBar.setNavigationOnClickListener {
            finishAffinity() // Closes the app and all parent activities
        }

        setLaunchActivityClickListener(binding.autocompleteButton, PlaceAutocompleteActivity::class.java)
        setLaunchActivityClickListener(binding.autocompleteAddressButton, AutocompleteAddressActivity::class.java)
        setLaunchActivityClickListener(binding.programmaticAutocompleteButton, ProgrammaticAutocompleteGeocodingActivity::class.java)
        setLaunchActivityClickListener(binding.currentPlaceButton, CurrentPlaceActivity::class.java)
        setLaunchActivityClickListener(binding.placeAndPhotoButton, PlaceDetailsAndPhotosActivity::class.java)
        setLaunchActivityClickListener(binding.isOpenButton, PlaceIsOpenActivity::class.java)

        Log.i(TestSignals.TAG, TestSignals.READY)
        if (savedInstanceState == null) {
            binding.currentPlaceButton.postDelayed({
                Log.i(TestSignals.TAG, TestSignals.MAIN_AUTO_CLICK_CURRENT_PLACE)
                binding.currentPlaceButton.performClick()
            }, TestSignals.MAIN_AUTO_CLICK_DELAY_MS)
        }
    }

    private fun setLaunchActivityClickListener(button: Button, activityClassToLaunch: Class<out Activity>) {
        button.setOnClickListener {
            val intent = Intent(this@MainActivity, activityClassToLaunch)
            startActivity(intent)
        }
    }
}
