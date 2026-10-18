@file:OptIn(ExperimentalMaterial3Api::class)

package org.janusknot.janus

import androidx.compose.foundation.clickable
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.layout.Box
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier

@Composable
fun ContactsScreen(model: AppModel, go: (String) -> Unit) {
    var menu by remember { mutableStateOf(false) }
    val waiting = model.contacts.filter { !it.confirmed }
    val active = model.contacts.filter { it.confirmed && !it.dormant }
    val dormant = model.contacts.filter { it.confirmed && it.dormant }
    Screen("Janus", back = null, actions = {
        Box {
            IconButton(onClick = { menu = true }) { Icon(Icons.Default.Add, contentDescription = "New") }
            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                listOf("Create an invitation" to "invite", "Answer an invitation" to "answer", "Networks" to "networks")
                    .forEach { (text, route) ->
                        DropdownMenuItem(text = { Text(text) }, onClick = {
                            menu = false
                            go(route)
                        })
                    }
            }
        }
    }) {
        model.trouble?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        if (!model.hardwareBacked) {
            Note("This device has no secure hardware for the storage key: software alone protects your conversations.")
        }
        if (model.networks.isEmpty()) {
            Button(onClick = { go("networks") }) { Text("Install a network to start") }
        }
        if (model.invitation == AppModel.Invitation.Answered) {
            Button(onClick = { go("invite") }) { Text("Your invitation was answered: type the safety words") }
        }
        if (waiting.isNotEmpty()) {
            Heading("Waiting for the safety words")
            waiting.forEach { contact ->
                ListItem(
                    headlineContent = { Text("New contact") },
                    modifier = Modifier.clickable { go("confirm/${contact.id}") },
                )
            }
        }
        Heading("Contacts")
        if (active.isEmpty()) Note("No contacts yet. Create an invitation, or answer one.")
        active.forEach { contact ->
            ListItem(
                headlineContent = { Text(contact.name) },
                trailingContent = { if (contact.id in model.unread) Badge() },
                modifier = Modifier.clickable { go("chat/${contact.id}") },
            )
        }
        if (dormant.isNotEmpty()) {
            Heading("Dormant")
            dormant.forEach { contact ->
                ListItem(
                    headlineContent = { Text(contact.name) },
                    modifier = Modifier.clickable { go("chat/${contact.id}") },
                )
            }
            Note("Nothing heard from these contacts for a year. Silence can be forged, so they stay until you close them.")
        }
    }
}
