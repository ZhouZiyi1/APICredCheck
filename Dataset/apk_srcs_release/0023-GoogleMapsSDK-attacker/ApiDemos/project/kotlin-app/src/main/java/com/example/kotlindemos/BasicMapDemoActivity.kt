/*
 * Copyright 2018 Google LLC
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

package com.example.kotlindemos

import android.os.Bundle
import android.util.Log
import android.widget.TextView

import com.google.android.gms.maps.CameraUpdateFactory
import com.google.android.gms.maps.GoogleMap
import com.google.android.gms.maps.OnMapReadyCallback
import com.google.android.gms.maps.SupportMapFragment
import com.google.android.gms.maps.model.LatLng
import com.google.android.gms.maps.model.MarkerOptions

/**
 * This shows how to create a simple activity with a map and a marker on the map.
 */
// [START maps_android_sample_basic_map]
class BasicMapDemoActivity : SamplesBaseActivity(), OnMapReadyCallback {

    val SYDNEY = LatLng(-33.862, 151.21)
    val ZOOM_LEVEL = 13f
    private var resultView: TextView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(com.example.common_ui.R.layout.basic_demo)
        applyInsets(findViewById(com.example.common_ui.R.id.map_container))
        resultView = findViewById(com.example.common_ui.R.id.api_call_result)
        startSdkCall()
        val mapFragment : SupportMapFragment? =
                supportFragmentManager.findFragmentById(com.example.common_ui.R.id.map) as? SupportMapFragment
        if (mapFragment == null) {
            failSdkCall("SupportMapFragment was null")
            completeSdkCall()
            return
        }
        mapFragment.getMapAsync(this)
    }

    /**
     * This is where we can add markers or lines, add listeners or move the camera. In this case,
     * we just move the camera to Sydney and add a marker in Sydney.
     */
    override fun onMapReady(googleMap: GoogleMap) {
        try {
            googleMap.moveCamera(CameraUpdateFactory.newLatLngZoom(SYDNEY, ZOOM_LEVEL))
            val marker = googleMap.addMarker(MarkerOptions().position(SYDNEY))
            if (marker == null) {
                failSdkCall("GoogleMap.addMarker returned null")
                return
            }
            val message = getString(
                com.example.common_ui.R.string.api_call_success,
                SYDNEY.latitude,
                SYDNEY.longitude,
                ZOOM_LEVEL,
                marker.id
            )
            showResult(message)
            Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_SUCCESS}: $message")
        } catch (exception: RuntimeException) {
            failSdkCall(exception.message ?: exception.javaClass.simpleName, exception)
        } finally {
            completeSdkCall()
        }
    }

    private fun startSdkCall() {
        val message = getString(com.example.common_ui.R.string.api_call_start)
        showResult(message)
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_START)
    }

    private fun failSdkCall(message: String, throwable: Throwable? = null) {
        showResult(getString(com.example.common_ui.R.string.api_call_failure, message))
        if (throwable == null) {
            Log.e(TestSignals.TAG, "${TestSignals.SDK_CALL_FAILURE}: $message")
        } else {
            Log.e(TestSignals.TAG, "${TestSignals.SDK_CALL_FAILURE}: $message", throwable)
        }
    }

    private fun completeSdkCall() {
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
    }

    private fun showResult(message: String) {
        resultView?.text = message
    }
}
// [END maps_android_sample_basic_map]
