@file:OptIn(ExperimentalMaterial3Api::class)

package org.janusknot.janus

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.janus_ffi.HistoryEntry
import uniffi.janus_ffi.JanusException

@Composable
fun ChatScreen(model: AppModel, contact: String, back: () -> Unit) {
    val scope = rememberCoroutineScope()
    val entries = model.histories[contact].orEmpty()
    val info = model.contacts.firstOrNull { it.id == contact }
    val dormant = info?.dormant == true
    var draft by remember { mutableStateOf("") }
    var failure by remember { mutableStateOf<String?>(null) }
    var closing by remember { mutableStateOf(false) }
    val list = rememberLazyListState()
    DisposableEffect(contact) {
        model.openChat = contact
        onDispose { if (model.openChat == contact) model.openChat = null }
    }
    LaunchedEffect(contact) { model.load(contact) }
    LaunchedEffect(entries.size) {
        if (entries.isNotEmpty()) list.animateScrollToItem(entries.lastIndex + if (dormant) 1 else 0)
    }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(info?.name.orEmpty()) },
                navigationIcon = { BackButton(back) },
                actions = { TextButton(onClick = { closing = true }) { Text("Close") } },
            )
        },
        bottomBar = {
            Column(Modifier.padding(8.dp)) {
                Failure(failure)
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(draft, { draft = it }, Modifier.weight(1f), placeholder = { Text("Message") })
                    Button(onClick = {
                        val text = draft
                        draft = ""
                        scope.launch {
                            failure = null
                            try {
                                model.send(text, contact)
                            } catch (e: JanusException) {
                                draft = text
                                failure = describe(e)
                            }
                        }
                    }, enabled = draft.isNotBlank()) { Text("Send") }
                }
            }
        },
    ) { padding ->
        LazyColumn(
            Modifier.padding(padding).fillMaxSize(),
            state = list,
            contentPadding = PaddingValues(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (dormant) item { Note("Nothing heard from this contact for a year.") }
            items(entries.size) { i -> Bubble(entries[i]) }
        }
    }
    if (closing) {
        AlertDialog(
            onDismissRequest = { closing = false },
            title = { Text("Close this conversation?") },
            text = { Text("Ends the session on both phones and deletes its history from this one.") },
            confirmButton = {
                TextButton(onClick = {
                    closing = false
                    scope.launch {
                        try {
                            model.close(contact)
                            back()
                        } catch (e: JanusException) {
                            failure = describe(e)
                        }
                    }
                }) { Text("Close and delete") }
            },
            dismissButton = { TextButton(onClick = { closing = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun Bubble(entry: HistoryEntry) {
    val text = runCatching { entry.data.decodeToString(throwOnInvalidSequence = true) }
        .getOrElse { "[${entry.data.size} bytes]" }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (entry.mine) Arrangement.End else Arrangement.Start) {
        Surface(
            color = if (entry.mine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.widthIn(max = 280.dp),
        ) {
            SelectionContainer { Text(text, Modifier.padding(10.dp)) }
        }
    }
}
