@file:OptIn(ExperimentalMaterial3Api::class)

package org.janusknot.janus

import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

/** A titled, scrolling screen with a back arrow when `back` is given. */
@Composable
fun Screen(
    title: String,
    back: (() -> Unit)?,
    actions: @Composable RowScope.() -> Unit = {},
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = { if (back != null) BackButton(back) },
                actions = actions,
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            content = content,
        )
    }
}

@Composable
fun BackButton(back: () -> Unit) {
    IconButton(onClick = back) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
}

@Composable
fun Heading(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium)
}

@Composable
fun Note(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
fun Failure(text: String?) {
    if (text != null) Text(text, color = MaterialTheme.colorScheme.error)
}

/** One of `options`, as radio buttons. */
@Composable
fun <T> Choice(label: String, options: List<T>, selected: T, text: (T) -> String, select: (T) -> Unit) {
    Column {
        Text(label, style = MaterialTheme.typography.labelLarge)
        options.forEach { option ->
            Row(
                Modifier.fillMaxWidth().selectable(option == selected, role = Role.RadioButton) { select(option) },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = option == selected, onClick = null)
                Text(text(option), Modifier.padding(start = 8.dp))
            }
        }
    }
}

/** The installed networks, the first (the default) preselected by the caller. */
@Composable
fun NetworkPicker(model: AppModel, selected: String, select: (String) -> Unit) {
    val names = model.networks.associate { it.id to it.name }
    Choice("Network", model.networks.map { it.id }, selected, { names[it].orEmpty() }, select)
}

/** The network id in groups of 4 hex digits, for people to compare. */
fun fingerprint(id: String): String = id.chunked(4).joinToString(" ")
