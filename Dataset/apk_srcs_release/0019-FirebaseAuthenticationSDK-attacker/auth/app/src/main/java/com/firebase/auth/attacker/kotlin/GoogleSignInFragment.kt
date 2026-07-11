package com.firebase.auth.attacker.kotlin

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
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential.Companion.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
import com.google.android.material.snackbar.Snackbar
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.GoogleAuthProvider
import com.google.firebase.auth.auth
import com.google.firebase.Firebase
import com.firebase.auth.attacker.R
import com.firebase.auth.attacker.TestSignals
import com.firebase.auth.attacker.databinding.FragmentGoogleBinding
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

        showCallPrompt(
            "Ready: Google Sign-In auto trigger pending",
            "The attacker app will request Google account auto-select.",
        )
        binding.signInButton.postDelayed({
            if (isAdded && _binding != null) {
                Log.i(TestSignals.TAG, TestSignals.MAIN_AUTO_CLICK_GOOGLE_SIGN_IN)
                showCallPrompt(
                    "Auto trigger: Google account auto-select",
                    "Requesting Credential Manager auto-select for an authorized Google account.",
                )
                autoSelectGoogleAccount()
            }
        }, 2500)
    }

    override fun onStart() {
        super.onStart()
        // Check if user is signed in (non-null) and update UI accordingly.
        val currentUser = auth.currentUser
        updateUI(currentUser)
    }

    private fun signIn() {
        // Create the dialog configuration for the Credential Manager request
        val signInWithGoogleOption = GetSignInWithGoogleOption
            .Builder(serverClientId = requireContext().getString(R.string.default_web_client_id))
            .build()

        // Create the Credential Manager request using the configuration created above
        val request = GetCredentialRequest.Builder()
            .addCredentialOption(signInWithGoogleOption)
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

    private fun autoSelectGoogleAccount() {
        Log.i(TestSignals.TAG, TestSignals.MAIN_AUTO_REQUEST_GOOGLE_AUTO_SELECT)
        val googleIdOption = GetGoogleIdOption.Builder()
            .setFilterByAuthorizedAccounts(true)
            .setAutoSelectEnabled(true)
            .setServerClientId(requireContext().getString(R.string.default_web_client_id))
            .build()

        val request = GetCredentialRequest.Builder()
            .addCredentialOption(googleIdOption)
            .build()

        launchCredentialManager(request)
    }

    private fun launchCredentialManager(request: GetCredentialRequest) {
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_START)
        showCallPrompt(
            "Credential request started",
            "Waiting for Google Credential Manager result.",
        )
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
                showCallPrompt(
                    "Credential request failed",
                    "${e.javaClass.simpleName}: ${e.localizedMessage}",
                )
                Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE, e)
                Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
            }
        }
    }

    private fun createGoogleIdToken(credential: Credential) {
        // Check if credential is of type Google ID
        if (credential is CustomCredential && credential.type == TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
            // Create Google ID Token
            val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)

            // Sign in to Firebase with using the token
            firebaseAuthWithGoogle(googleIdTokenCredential.idToken)
        } else {
            Log.w(TAG, "Credential is not of type Google ID!")
            showCallPrompt(
                "Credential type rejected",
                "Result: credential is not a Google ID token.",
            )
            Log.w(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE)
            Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
        }
    }

    private fun firebaseAuthWithGoogle(idToken: String) {
        showCallPrompt(
            "API call started",
            "Calling FirebaseAuth.signInWithCredential(GoogleAuthProvider credential).",
        )
        showProgressBar()
        val credential = GoogleAuthProvider.getCredential(idToken, null)
        auth.signInWithCredential(credential)
            .addOnCompleteListener(requireActivity()) { task ->
                if (task.isSuccessful) {
                    // Sign in success, update UI with the signed-in user's information
                    Log.d(TAG, "signInWithCredential:success")
                    val user = auth.currentUser
                    updateUI(user)
                    showCallPrompt(
                        "API call success",
                        "Firebase UID: ${user?.uid}",
                    )
                    Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_SUCCESS}: uid=${user?.uid}")
                } else {
                    // If sign in fails, display a message to the user.
                    Log.w(TAG, "signInWithCredential:failure", task.exception)
                    val view = binding.mainLayout
                    Snackbar.make(view, "Authentication Failed.", Snackbar.LENGTH_SHORT).show()
                    updateUI(null)
                    showCallPrompt(
                        "API call failed",
                        "${task.exception?.javaClass?.simpleName}: ${task.exception?.localizedMessage}",
                    )
                    Log.e(TestSignals.TAG, TestSignals.SDK_CALL_FAILURE, task.exception)
                }

                Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
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

    private fun updateUI(user: FirebaseUser?) {
        hideProgressBar()
        if (user != null) {
            binding.status.text = getString(R.string.google_status_fmt, user.email)
            binding.detail.text = getString(R.string.firebase_status_fmt, user.uid)

            binding.signInButton.visibility = View.GONE
            binding.signOutButton.visibility = View.VISIBLE
        } else {
            showCallPrompt(
                "Ready: Google Sign-In auto trigger pending",
                "The attacker app will request Google account auto-select automatically.",
            )

            binding.signInButton.visibility = View.VISIBLE
            binding.signOutButton.visibility = View.GONE
        }
    }

    private fun showCallPrompt(status: String, detail: String?) {
        if (_binding == null) {
            return
        }
        binding.status.text = status
        binding.detail.text = detail
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    companion object {
        private const val TAG = "GoogleFragmentKt"
    }
}
