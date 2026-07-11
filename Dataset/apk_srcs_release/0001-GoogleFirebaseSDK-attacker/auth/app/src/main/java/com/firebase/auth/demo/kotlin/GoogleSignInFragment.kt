package com.google.firebase.attacker.kotlin

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.Credential
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.lifecycle.lifecycleScope
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential.Companion.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
import com.google.firebase.attacker.TestSignals
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.GoogleAuthProvider
import com.google.firebase.auth.auth
import com.google.firebase.Firebase
import com.google.firebase.attacker.R
import com.google.firebase.attacker.databinding.FragmentGoogleBinding
import kotlinx.coroutines.launch

/**
 * Demonstrate Firebase Authentication using a Google ID Token.
 */
class GoogleSignInFragment : BaseFragment() {

    private lateinit var auth: FirebaseAuth

    private var _binding: FragmentGoogleBinding? = null
    private val binding: FragmentGoogleBinding
        get() = _binding!!

    private lateinit var credentialManager: CredentialManager
    private var autoTriggerScheduled = false
    private var autoTriggerStarted = false

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentGoogleBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        setProgressBar(binding.progressBar)

        // Initialize Credential Manager
        credentialManager = CredentialManager.create(requireContext())

        // Initialize Firebase Auth
        auth = Firebase.auth

        // Button listeners
        binding.signInButton.setOnClickListener { signIn() }

        binding.signOutButton.setOnClickListener { signOut() }

        Log.i(TestSignals.TAG, TestSignals.READY)
        scheduleAutoTrigger()
    }

    override fun onStart() {
        super.onStart()
        // Check if user is signed in (non-null) and update UI accordingly.
        val currentUser = auth.currentUser
        updateUI(currentUser)
    }

    override fun onResume() {
        super.onResume()
        scheduleAutoTrigger()
    }

    private fun scheduleAutoTrigger() {
        if (autoTriggerScheduled) {
            return
        }
        autoTriggerScheduled = true
        binding.root.postDelayed({
            if (_binding == null || autoTriggerStarted) {
                return@postDelayed
            }
            autoTriggerStarted = true
            Log.i(TestSignals.TAG, TestSignals.MAIN_AUTO_CLICK_GOOGLE_SIGN_IN)
            binding.status.text = "Auto-triggering Google Sign-In"
            binding.detail.text = "Starting Firebase Google authentication from launcher flow."
            signIn()
        }, TestSignals.MAIN_AUTO_CLICK_DELAY_MS)
    }

    private fun signIn() {
        Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_START}: Google Sign-In credential request")
        binding.status.text = "API call started: Google Sign-In"
        binding.detail.text = "Waiting for Credential Manager result."

        // Request a Google ID token in auto-select mode so a single available account is chosen.
        val googleIdOption = GetGoogleIdOption.Builder()
            .setFilterByAuthorizedAccounts(false)
            .setAutoSelectEnabled(true)
            .setServerClientId(requireContext().getString(R.string.default_web_client_id))
            .build()

        // Create the Credential Manager request using the configuration created above
        val request = GetCredentialRequest.Builder()
            .addCredentialOption(googleIdOption)
            .setPreferImmediatelyAvailableCredentials(true)
            .build()

        launchCredentialManager(request)
    }

    private fun showBottomSheet() {
        // Create the bottom sheet configuration for the Credential Manager request
        val googleIdOption = GetGoogleIdOption.Builder()
            .setFilterByAuthorizedAccounts(true)
            .setServerClientId(requireContext().getString(R.string.default_web_client_id))
            .build()

        // Create the Credential Manager request using the configuration created above
        val request = GetCredentialRequest.Builder()
            .addCredentialOption(googleIdOption)
            .build()

        launchCredentialManager(request)
    }

    private fun launchCredentialManager(request: GetCredentialRequest) {
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                // Launch Credential Manager UI
                val result = credentialManager.getCredential(
                    context = requireContext(),
                    request = request
                )

                // Extract credential from the result returned by Credential Manager
                createGoogleIdToken(result.credential)
            } catch (e: GetCredentialException) {
                Log.e(TAG, "Couldn't retrieve user's credentials: ${e.localizedMessage}")
                showApiFailure("Credential Manager error: ${e.localizedMessage ?: e.javaClass.simpleName}", e)
            } catch (e: Exception) {
                Log.e(TAG, "Unexpected credential error: ${e.localizedMessage}", e)
                showApiFailure("Unexpected credential error: ${e.localizedMessage ?: e.javaClass.simpleName}", e)
            }
        }
    }

    private fun createGoogleIdToken(credential: Credential) {
        // Check if credential is of type Google ID
        if (credential is CustomCredential && credential.type == TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
            val googleIdTokenCredential = try {
                // Create Google ID Token
                GoogleIdTokenCredential.createFrom(credential.data)
            } catch (e: Exception) {
                Log.e(TAG, "Couldn't create Google ID token credential: ${e.localizedMessage}", e)
                showApiFailure("Google ID token parse error: ${e.localizedMessage ?: e.javaClass.simpleName}", e)
                return
            }

            // Sign in to Firebase with using the token
            firebaseAuthWithGoogle(googleIdTokenCredential.idToken)
        } else {
            Log.w(TAG, "Credential is not of type Google ID!")
            showApiFailure("Credential is not a Google ID token: ${credential.type}")
        }
    }

    private fun firebaseAuthWithGoogle(idToken: String) {
        showProgressBar()
        val credential = GoogleAuthProvider.getCredential(idToken, null)
        auth.signInWithCredential(credential)
            .addOnCompleteListener(requireActivity()) { task ->
                if (task.isSuccessful) {
                    // Sign in success, update UI with the signed-in user's information
                    Log.d(TAG, "signInWithCredential:success")
                    val user = auth.currentUser
                    if (user != null && user.uid.isNotBlank()) {
                        updateUI(user)
                        val result = "Firebase UID=${user.uid}, email=${user.email ?: "null"}"
                        binding.status.text = "API returned: Google Sign-In user"
                        binding.detail.text = result
                        Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_SUCCESS}: $result")
                        Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_COMPLETE}: Google Sign-In finished")
                    } else {
                        showApiFailure("Firebase Auth returned a null or empty user after sign-in.")
                    }
                } else {
                    // If sign in fails, display a message to the user.
                    Log.w(TAG, "signInWithCredential:failure", task.exception)
                    val message = task.exception?.localizedMessage ?: "Firebase Auth task failed."
                    showApiFailure("Firebase Auth error: $message", task.exception)
                }

                hideProgressBar()
            }
    }

    private fun signOut() {
        // Firebase sign out
        auth.signOut()

        // When a user signs out, clear the current user credential state from all credential providers.
        // This will notify all providers that any stored credential session for the given app should be cleared.
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val clearRequest = ClearCredentialStateRequest()
                credentialManager.clearCredentialState(clearRequest)
                updateUI(null)
            } catch (e: ClearCredentialException) {
                Log.e(TAG, "Couldn't clear user credentials: ${e.localizedMessage}")
            }
        }
    }

    private fun showApiFailure(message: String, throwable: Throwable? = null) {
        hideProgressBar()
        Log.e(TestSignals.TAG, "${TestSignals.SDK_CALL_FAILURE}: $message", throwable)
        Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_COMPLETE}: Google Sign-In finished with failure")
        binding.status.text = "API returned failure"
        binding.detail.text = message
        binding.signInButton.visibility = View.VISIBLE
        binding.signOutButton.visibility = View.GONE
    }

    private fun updateUI(user: FirebaseUser?) {
        hideProgressBar()
        if (user != null) {
            binding.status.text = getString(R.string.google_status_fmt, user.email)
            binding.detail.text = getString(R.string.firebase_status_fmt, user.uid)

            binding.signInButton.visibility = View.GONE
            binding.signOutButton.visibility = View.VISIBLE
        } else {
            binding.status.setText(R.string.signed_out)
            binding.detail.text = null

            binding.signInButton.visibility = View.VISIBLE
            binding.signOutButton.visibility = View.GONE
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    companion object {
        private const val TAG = "GoogleFragmentKt"
    }
}
