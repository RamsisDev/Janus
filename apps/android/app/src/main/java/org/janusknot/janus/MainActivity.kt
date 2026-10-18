package org.janusknot.janus

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import kotlinx.coroutines.launch

class MainActivity : FragmentActivity() {
    private var locked by mutableStateOf(true)
    private var asking = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Blocks screenshots and screen recording, and blanks the app in the recent apps.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val model = (application as JanusApplication).model
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) { model.run() }
        }
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Box {
                    Janus(model)
                    if (locked) LockScreen { unlock() }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        unlock()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) locked = true
    }

    /** Unlocks with the device's own authentication: biometrics or the screen lock. */
    private fun unlock() {
        if (!locked || asking) return
        val allowed = BIOMETRIC_WEAK or DEVICE_CREDENTIAL
        if (BiometricManager.from(this).canAuthenticate(allowed) != BiometricManager.BIOMETRIC_SUCCESS) {
            // shortcut: a device without a screen lock has nothing to unlock with, so the app
            // opens; upgrade to an app passphrase if the threat model needs one there.
            locked = false
            return
        }
        asking = true
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                asking = false
                locked = false
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                asking = false
            }
        }
        val prompt = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock Janus")
            .setAllowedAuthenticators(allowed)
            .build()
        BiometricPrompt(this, ContextCompat.getMainExecutor(this), callback).authenticate(prompt)
    }
}

@Composable
private fun LockScreen(unlock: () -> Unit) {
    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Button(onClick = unlock) { Text("Unlock") }
        }
    }
}

@Composable
private fun Janus(model: AppModel) {
    val nav = rememberNavController()
    val back: () -> Unit = { nav.popBackStack() }
    NavHost(nav, startDestination = "contacts") {
        composable("contacts") { ContactsScreen(model) { nav.navigate(it) } }
        composable("invite") { InviteScreen(model, back) }
        composable("answer") { AnswerScreen(model, back) }
        composable("networks") { NetworksScreen(model, back) }
        composable("chat/{id}") { ChatScreen(model, it.arguments?.getString("id").orEmpty(), back) }
        composable("confirm/{id}") { ConfirmScreen(model, it.arguments?.getString("id").orEmpty(), back) }
    }
}
