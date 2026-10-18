@file:OptIn(ExperimentalMaterial3Api::class)

package org.janusknot.janus

import android.util.Base64
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ListItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import java.io.IOException
import kotlinx.coroutines.launch
import uniffi.janus_ffi.JanusException
import uniffi.janus_ffi.NetworkInfo
import uniffi.janus_ffi.readNetwork

/**
 * The installed networks, and installing one from a QR code or a file. The profile is shown
 * before it is installed, since a substituted one would route the user through someone else's
 * servers.
 */
@Composable
fun NetworksScreen(model: AppModel, back: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var found by remember { mutableStateOf<Pair<ByteArray, NetworkInfo>?>(null) }
    var failure by remember { mutableStateOf<String?>(null) }
    fun offer(profile: ByteArray) {
        failure = null
        try {
            found = profile to readNetwork(profile)
        } catch (e: JanusException) {
            failure = describe(e)
        }
    }
    val scan = rememberLauncherForActivityResult(ScanContract()) { result ->
        val text = result.contents ?: return@rememberLauncherForActivityResult
        // shortcut: one QR code holds base64 text of up to ~2 KB of profile (one or two
        // authorities); move to binary or multi-part codes when profiles outgrow it.
        try {
            offer(Base64.decode(text, Base64.DEFAULT))
        } catch (e: IllegalArgumentException) {
            failure = describe(JanusException.BadProfile())
        }
    }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        try {
            context.contentResolver.openInputStream(uri)?.use { offer(it.readBytes()) }
        } catch (e: IOException) {
            failure = describe(e)
        }
    }
    Screen("Networks", back) {
        Heading("Installed")
        if (model.networks.isEmpty()) Note("None yet")
        model.networks.forEach { network ->
            ListItem(
                headlineContent = { Text(network.name) },
                supportingContent = { Text(fingerprint(network.id), fontFamily = FontFamily.Monospace) },
            )
        }
        Heading("Install a network")
        Button(onClick = {
            scan.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setBeepEnabled(false)
                    .setPrompt("The network's QR code")
            )
        }) { Text("Scan a QR code") }
        OutlinedButton(onClick = { pick.launch(arrayOf("*/*")) }) { Text("Choose a file") }
        Note("Only from a source you verified: a QR code shown to you in person, or a file from someone you trust.")
        Failure(failure)
    }
    found?.let { (profile, network) ->
        AlertDialog(
            onDismissRequest = { found = null },
            title = { Text("Install ${network.name}?") },
            text = { Text("Check that this id matches your source:\n${fingerprint(network.id)}", fontFamily = FontFamily.Monospace) },
            confirmButton = {
                TextButton(onClick = {
                    found = null
                    scope.launch {
                        try {
                            model.install(profile)
                        } catch (e: JanusException) {
                            failure = describe(e)
                        }
                    }
                }) { Text("Install") }
            },
            dismissButton = { TextButton(onClick = { found = null }) { Text("Cancel") } },
        )
    }
}
