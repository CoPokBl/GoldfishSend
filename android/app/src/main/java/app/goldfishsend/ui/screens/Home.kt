package app.goldfishsend.ui.screens

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ChatBubble
import androidx.compose.material.icons.rounded.ChatBubbleOutline
import androidx.compose.material.icons.rounded.PersonAdd
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material3.Badge
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.Session
import app.goldfishsend.db.ChatSummary
import app.goldfishsend.ui.components.Avatar
import app.goldfishsend.ui.components.StatusLine
import app.goldfishsend.ui.components.StatusTicks
import app.goldfishsend.ui.components.rememberQuery
import app.goldfishsend.ui.components.shortTime
import androidx.compose.foundation.clickable

enum class Tab { CHATS, SECURITY, SETTINGS }

@Composable
fun HomeScreen(
    s: Session,
    openChat: (Long) -> Unit,
    addContact: () -> Unit,
    openPassphrase: () -> Unit,
) {
    var tab by rememberSaveable { mutableIntStateOf(0) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                val items = listOf(
                    Triple("Chats", Icons.Rounded.ChatBubble, Icons.Rounded.ChatBubbleOutline),
                    Triple("Security", Icons.Rounded.Shield, Icons.Outlined.Shield),
                    Triple("Settings", Icons.Rounded.Settings, Icons.Outlined.Settings),
                )
                items.forEachIndexed { i, (label, on, off) ->
                    NavigationBarItem(
                        selected = tab == i,
                        onClick = { tab = i },
                        icon = { Icon(if (tab == i) on else off, null) },
                        label = { Text(label) },
                    )
                }
            }
        },
    ) { pad ->
        Box(Modifier.padding(bottom = pad.calculateBottomPadding())) {
            AnimatedContent(tab, transitionSpec = { fadeIn() togetherWith fadeOut() }, label = "tab") { t ->
                when (Tab.entries[t]) {
                    Tab.CHATS -> ChatList(s, openChat, addContact)
                    Tab.SECURITY -> SecurityScreen(s, openPassphrase = openPassphrase, openChats = { tab = 0 })
                    Tab.SETTINGS -> SettingsScreen(s, openPassphrase)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChatList(s: Session, openChat: (Long) -> Unit, addContact: () -> Unit) {
    val chats by rememberQuery(s) { it.repo.chatSummaries(System.currentTimeMillis()) }
    val busy by Mailboxes.busy.collectAsState()
    val prefsVersion by Graph.prefs.version.collectAsState()
    val pushOk = prefsVersion.let { Graph.prefs.pushStatus == "ok" }
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        topBar = { LargeTopAppBar(title = { Text("Chats") }, scrollBehavior = scroll) },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = addContact,
                icon = { Icon(Icons.Rounded.PersonAdd, null) },
                text = { Text("Add contact") },
                expanded = chats.isNullOrEmpty() || !scroll.state.collapsedFraction.let { it > 0.5f },
            )
        },
        contentWindowInsets = androidx.compose.foundation.layout.WindowInsets(0),
    ) { pad ->
        Column(Modifier.padding(top = pad.calculateTopPadding()).fillMaxSize()) {
            StatusLine(!pushOk && Graph.prefs.onboarded, "Notifications aren't connected yet. Check your push app.", action = null)
            StatusLine(pushOk && busy && chats.isNullOrEmpty(), "Getting ready…")
            val list = chats
            if (list != null && list.isEmpty()) {
                EmptyChats(addContact)
            } else {
                LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 96.dp)) {
                    items(list.orEmpty(), key = { it.contact.id }) { c ->
                        ChatRow(c, Modifier.animateItem()) { openChat(c.contact.id) }
                    }
                }
            }
        }
    }
}

@Composable
private fun ChatRow(c: ChatSummary, modifier: Modifier, onClick: () -> Unit) {
    val unread = c.contact.unread
    ListItem(
        modifier = modifier.clickable(onClick = onClick).padding(horizontal = 4.dp),
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        leadingContent = { Avatar(c.contact.name, c.contact.id, 52.dp) },
        headlineContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    c.contact.name,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    fontWeight = if (unread > 0) FontWeight.SemiBold else FontWeight.Normal,
                    modifier = Modifier.weight(1f, fill = false),
                )
                if (c.contact.verified) {
                    Spacer(Modifier.width(4.dp))
                    Icon(Icons.Rounded.Verified, "Verified", Modifier.size(16.dp), tint = MaterialTheme.colorScheme.primary)
                }
                if (c.contact.timerSecs > 0) {
                    Spacer(Modifier.width(4.dp))
                    Icon(Icons.Rounded.Timer, "Disappearing messages on", Modifier.size(14.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        },
        supportingContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (c.lastOutgoing && c.lastBody != null) {
                    StatusTicks(c.lastStatus, MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.width(4.dp))
                }
                Text(
                    when {
                        c.contact.unreachable -> "Can't be reached right now"
                        c.lastBody != null -> c.lastBody
                        else -> "Say hi 👋"
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    color = if (unread > 0) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        trailingContent = {
            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    shortTime(c.lastTs ?: c.contact.lastActivity),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (unread > 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (unread > 0) {
                    Badge(containerColor = MaterialTheme.colorScheme.primary) { Text(if (unread > 99) "99+" else "$unread") }
                } else {
                    Spacer(Modifier.height(16.dp))
                }
            }
        },
    )
}

@Composable
private fun EmptyChats(addContact: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            Modifier.size(96.dp).background(MaterialTheme.colorScheme.secondaryContainer, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Rounded.PersonAdd, null, Modifier.size(44.dp), tint = MaterialTheme.colorScheme.onSecondaryContainer)
        }
        Spacer(Modifier.height(20.dp))
        Text("No chats yet", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Text(
            "Add someone by scanning their code, or show them yours.",
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(80.dp))
    }
}
