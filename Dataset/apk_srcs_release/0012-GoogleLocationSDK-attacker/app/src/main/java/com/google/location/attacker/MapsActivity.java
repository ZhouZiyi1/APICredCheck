package com.google.location.attacker;

import androidx.annotation.NonNull;
import androidx.core.app.ActivityCompat;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;

import android.Manifest;
import android.content.pm.PackageManager;
import android.location.Location;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationServices;
import com.google.android.gms.maps.CameraUpdateFactory;
import com.google.android.gms.maps.GoogleMap;
import com.google.android.gms.maps.OnMapReadyCallback;
import com.google.android.gms.maps.SupportMapFragment;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.maps.model.MarkerOptions;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.location.attacker.databinding.ActivityMapsBinding;

public class MapsActivity extends FragmentActivity implements OnMapReadyCallback {

    private GoogleMap mMap;
    private ActivityMapsBinding binding;
    private FusedLocationProviderClient fusedLocationClient;
    private static final int PERMISSION_REQUEST_CODE = 1001;
    private boolean mapLoaded;
    private Location lastLocation;
    private boolean sdkCallStarted;
    private boolean sdkCallCompleted;
    private boolean terminalSignalSent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMapsBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this);

        binding.btnGetLocation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                runLocationTest();
            }
        });

        showStatus("Ready. Maps SDK initialization and Location SDK call will start automatically.", false);
        Log.i(TestSignals.TAG, TestSignals.READY);
        if (savedInstanceState == null) {
            binding.map.postDelayed(new Runnable() {
                @Override
                public void run() {
                    initializeMapFragment();
                }
            }, TestSignals.MAP_INIT_DELAY_MS);
            binding.btnGetLocation.postDelayed(new Runnable() {
                @Override
                public void run() {
                    showStatus("Auto-triggering Google Location SDK call...", true);
                    Log.i(TestSignals.TAG, TestSignals.MAIN_AUTO_CLICK_GET_LOCATION);
                    binding.btnGetLocation.performClick();
                }
            }, TestSignals.MAIN_AUTO_CLICK_DELAY_MS);
        }
    }

    private void initializeMapFragment() {
        try {
            Log.i(TestSignals.TAG, TestSignals.MAP_INIT_START);
            showStatus("Initializing Google Maps SDK...", false);
            FragmentManager fragmentManager = getSupportFragmentManager();
            SupportMapFragment mapFragment = (SupportMapFragment) fragmentManager.findFragmentByTag("apicred_map");
            if (mapFragment == null) {
                mapFragment = SupportMapFragment.newInstance();
                fragmentManager.beginTransaction()
                        .replace(R.id.map, mapFragment, "apicred_map")
                        .commitNowAllowingStateLoss();
            }
            mapFragment.getMapAsync(this);
            binding.map.postDelayed(new Runnable() {
                @Override
                public void run() {
                    if (!mapLoaded && !terminalSignalSent) {
                        showStatus("Maps SDK load timed out; check API credential authorization.", true);
                        Log.e(TestSignals.TAG, TestSignals.MAP_LOAD_TIMEOUT + ": Maps SDK did not report onMapLoaded");
                        emitFailureIfReady("maps load timeout");
                    }
                }
            }, TestSignals.MAP_LOAD_TIMEOUT_MS);
        } catch (Exception exception) {
            String message = exception.getMessage() != null ? exception.getMessage() : exception.getClass().getSimpleName();
            showStatus("Maps SDK init failed: " + message, true);
            Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": map init failed: " + message, exception);
            terminalSignalSent = true;
            Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
        }
    }

    private void runLocationTest() {
        try {
            getCurrentLocation();
        } catch (Exception exception) {
            String message = exception.getMessage() != null ? exception.getMessage() : exception.getClass().getSimpleName();
            showStatus("SDK call failed: " + message, true);
            Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + message, exception);
        }
    }

    private void getCurrentLocation() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED
                && ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            showStatus("SDK call paused: location permission is missing.", true);
            Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": location permission missing");
            Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
            ActivityCompat.requestPermissions(
                    this,
                    new String[]{Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION},
                    PERMISSION_REQUEST_CODE
            );
            return;
        }

        showStatus("Calling Google Location SDK...", true);
        sdkCallStarted = true;
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_START);
        fusedLocationClient.getLastLocation()
                .addOnSuccessListener(this, new OnSuccessListener<Location>() {
                    @Override
                    public void onSuccess(Location location) {
                        if (location != null) {
                            LatLng currentLatLng = new LatLng(location.getLatitude(), location.getLongitude());
                            String returnValue = formatLocationReturnValue(location);
                            lastLocation = location;
                            if (mMap != null) {
                                updateMapForLocation(location);
                                showStatus("Location API returned: " + returnValue + "; waiting for Maps SDK load.", true);
                                maybeEmitSuccess();
                            } else {
                                showStatus("API returned: " + returnValue + "; map is not ready.", true);
                            }
                        } else {
                            showStatus("API returned: null", true);
                            Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": API returned null");
                            terminalSignalSent = true;
                        }
                    }
                })
                .addOnFailureListener(this, new OnFailureListener() {
                    @Override
                    public void onFailure(@NonNull Exception exception) {
                        String message = exception.getMessage() != null ? exception.getMessage() : exception.getClass().getSimpleName();
                        showStatus("SDK call failed: " + message, true);
                        Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + message, exception);
                        terminalSignalSent = true;
                    }
                })
                .addOnCompleteListener(this, new OnCompleteListener<Location>() {
                    @Override
                    public void onComplete(@NonNull Task<Location> task) {
                        sdkCallCompleted = true;
                        if (!task.isSuccessful()) {
                            showStatus("SDK call completed with failure.", false);
                            Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
                        } else {
                            maybeEmitSuccess();
                        }
                    }
                });
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (hasGrantedLocationPermission(grantResults)) {
                getCurrentLocation();
            } else {
                showStatus("SDK call failed: location permission denied.", true);
                Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": permission denied");
                Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
            }
        }
    }

    private boolean hasGrantedLocationPermission(@NonNull int[] grantResults) {
        for (int result : grantResults) {
            if (result == PackageManager.PERMISSION_GRANTED) {
                return true;
            }
        }
        return false;
    }

    private String formatLocationReturnValue(@NonNull Location location) {
        return "Location{"
                + "provider=" + location.getProvider()
                + ", lat=" + location.getLatitude()
                + ", lng=" + location.getLongitude()
                + ", accuracy=" + (location.hasAccuracy() ? location.getAccuracy() : "unknown")
                + ", time=" + location.getTime()
                + "}";
    }

    private void updateMapForLocation(@NonNull Location location) {
        if (mMap == null) {
            return;
        }
        LatLng currentLatLng = new LatLng(location.getLatitude(), location.getLongitude());
        mMap.clear();
        mMap.addMarker(new MarkerOptions().position(currentLatLng).title("My Location"));
        mMap.animateCamera(CameraUpdateFactory.newLatLngZoom(currentLatLng, 15));
    }

    private void maybeEmitSuccess() {
        if (terminalSignalSent || !sdkCallCompleted || lastLocation == null || !mapLoaded) {
            return;
        }
        String returnValue = formatLocationReturnValue(lastLocation);
        showStatus("Maps SDK loaded; Location API returned: " + returnValue, true);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_SUCCESS + ": mapLoaded=true; " + returnValue);
        terminalSignalSent = true;
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
    }

    private void emitFailureIfReady(String reason) {
        if (terminalSignalSent || !sdkCallStarted) {
            return;
        }
        terminalSignalSent = true;
        Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE + ": " + reason);
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE);
    }

    private void showStatus(String message, boolean toast) {
        binding.statusMessage.setText(message);
        if (toast) {
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Manipulates the map once available.
     * This callback is triggered when the map is ready to be used.
     * This is where we can add markers or lines, add listeners or move the camera. In this case,
     * we just add a marker near Sydney, Australia.
     * If Google Play services is not installed on the device, the user will be prompted to install
     * it inside the SupportMapFragment. This method will only be triggered once the user has
     * installed Google Play services and returned to the app.
     */
    @Override
    public void onMapReady(GoogleMap googleMap) {
        mMap = googleMap;
        Log.i(TestSignals.TAG, TestSignals.MAP_READY);
        mMap.setOnMapLoadedCallback(new GoogleMap.OnMapLoadedCallback() {
            @Override
            public void onMapLoaded() {
                mapLoaded = true;
                Log.i(TestSignals.TAG, TestSignals.MAP_LOADED);
                if (lastLocation != null) {
                    updateMapForLocation(lastLocation);
                }
                maybeEmitSuccess();
            }
        });

        LatLng shanghai = new LatLng(31.2304, 121.4737);
        mMap.addMarker(new MarkerOptions().position(shanghai).title("Waiting for device location"));
        mMap.moveCamera(CameraUpdateFactory.newLatLngZoom(shanghai, 11));
    }
}
