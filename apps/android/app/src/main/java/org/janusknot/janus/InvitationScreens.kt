package org.janusknot.janus

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.janus_ffi.JanusException

private val ROTATIONS = listOf<UByte>(1u, 5u, 10u, 120u)

private const val MISMATCH = "The words do not match. Check them and type them again. If they really " +
    "differ, someone may be in the middle: cancel, and invite again in person."

private val WORDS = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false)

private fun rotation(hours: UByte): String = when (hours.toInt()) {
    1 -> "Every hour"
    120 -> "Every 5 days"
    else -> "Every $hours hours"
}

/** A: picks the network and rotation, reads the 6 words out, then types B's safety words. */
@Composable
fun InviteScreen(model: AppModel, back: () -> Unit) {
    val scope = rememberCoroutineScope()
    var network by remember { mutableStateOf(model.networks.firstOrNull()?.id.orEmpty()) }
    var hours by remember { mutableStateOf<UByte>(10u) }
    var typed by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var failure by remember { mutableStateOf<String?>(null) }
    fun act(work: suspend () -> Unit) {
        scope.launch {
            failure = null
            try {
                work()
            } catch (e: JanusException.Rejected) {
                failure = MISMATCH
            } catch (e: JanusException) {
                failure = describe(e)
            }
        }
    }
    Screen("Invitation", back = {
        model.invitation = null
        back()
    }) {
        when (val invitation = model.invitation) {
            null -> {
                NetworkPicker(model, network) { network = it }
                Choice("Key rotation", ROTATIONS, hours, ::rotation) { hours = it }
                Note("The other person answers on the same network. Keys are replaced at least this often, even if nobody writes.")
                Button(onClick = { act { model.invite(network, hours) } }, enabled = network.isNotEmpty()) {
                    Text("Create the invitation")
                }
            }
            is AppModel.Invitation.Waiting -> {
                Heading("Read these 6 words to the other person")
                SelectionContainer {
                    Text(invitation.words, style = MaterialTheme.typography.headlineSmall, fontFamily = FontFamily.Monospace)
                }
                Note("In person or on a call, and tell them the network: ${invitation.network}. They have 10 minutes to answer.")
                Waiting("Waiting for the answer…")
            }
            AppModel.Invitation.Answered -> {
                Heading("They answered")
                Note("Ask them to read you the 3 words their phone shows, and type them.")
                OutlinedTextField(typed, { typed = it }, label = { Text("3 safety words") }, singleLine = true, keyboardOptions = WORDS)
                OutlinedTextField(name, { name = it }, label = { Text("Name for this contact") }, singleLine = true)
                Button(onClick = {
                    act {
                        model.verify(words(typed), name)
                        back()
                    }
                }, enabled = name.isNotEmpty()) { Text("Check the words") }
            }
        }
        Failure(failure)
    }
}

/** B: types the 6 words on the network the invitation names, then reads out the safety words. */
@Composable
fun AnswerScreen(model: AppModel, back: () -> Unit) {
    val scope = rememberCoroutineScope()
    var network by remember { mutableStateOf(model.networks.firstOrNull()?.id.orEmpty()) }
    var typed by remember { mutableStateOf("") }
    var failure by remember { mutableStateOf<String?>(null) }
    Screen("Answer", back = {
        if (model.answer == AppModel.Answer.Looking) model.answer = null
        back()
    }) {
        when (val answer = model.answer) {
            null -> {
                NetworkPicker(model, network) { network = it }
                Note("The network the other person named; if they named none, the default.")
                OutlinedTextField(typed, { typed = it }, label = { Text("6 words") }, keyboardOptions = WORDS)
                Button(onClick = {
                    scope.launch {
                        failure = null
                        try {
                            model.join(network, words(typed))
                        } catch (e: JanusException) {
                            failure = describe(e)
                        }
                    }
                }, enabled = network.isNotEmpty()) { Text("Answer") }
            }
            AppModel.Answer.Looking -> {
                Waiting("Looking for the invitation…")
                Note("An invitation lives 10 minutes.")
            }
            is AppModel.Answer.Joined -> ConfirmContent(model, answer.contact, answer.safetyWords, back)
        }
        Failure(failure)
    }
}

/** B, for a contact still waiting for the safety words, e.g. after a restart. */
@Composable
fun ConfirmScreen(model: AppModel, contact: String, back: () -> Unit) {
    var safetyWords by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(contact) { safetyWords = model.safetyWords(contact) }
    Screen("Safety words", back) {
        safetyWords?.let { ConfirmContent(model, contact, it, back) } ?: CircularProgressIndicator()
    }
}

@Composable
private fun ConfirmContent(model: AppModel, contact: String, safetyWords: String, done: () -> Unit) {
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    var failure by remember { mutableStateOf<String?>(null) }
    fun act(work: suspend () -> Unit) {
        scope.launch {
            try {
                work()
                done()
            } catch (e: JanusException) {
                failure = describe(e)
            }
        }
    }
    Heading("Read these 3 words to the other person")
    Text(safetyWords, style = MaterialTheme.typography.headlineSmall, fontFamily = FontFamily.Monospace)
    Note("They type them and tell you whether they match. Nothing is sent before.")
    OutlinedTextField(name, { name = it }, label = { Text("Name for this contact") }, singleLine = true)
    Button(onClick = { act { model.confirm(contact, name) } }, enabled = name.isNotEmpty()) {
        Text("They say the words match")
    }
    OutlinedButton(onClick = { act { model.close(contact) } }) { Text("They do not match") }
    Note("Words that do not match mean someone may be in the middle. Close this contact and invite again in person.")
    Failure(failure)
}

@Composable
private fun Waiting(text: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(Modifier.size(20.dp))
        Text(text)
    }
}
