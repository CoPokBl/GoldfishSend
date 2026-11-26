package app.goldfishsend.ui.screens

import androidx.compose.runtime.mutableStateOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.foundation.combinedClickable
import app.goldfishsend.ui.components.PinEntryDialog
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
import app.goldfishsend.ui.ContentReady
import app.goldfishsend.core.Graph
import app.goldfishsend.core.traced
import app.goldfishsend.core.Mailboxes
import app.goldfishsend.core.Session
import app.goldfishsend.db.ChatSummary
import app.goldfishsend.db.groupRefs
import app.goldfishsend.core.Groups
import app.goldfishsend.group.GroupModel
import app.goldfishsend.ui.components.GroupAvatar
import androidx.compose.material3.IconButton
import androidx.compose.material.icons.rounded.GroupAdd
import app.goldfishsend.ui.components.Avatar
import app.goldfishsend.ui.components.StatusLine
import app.goldfishsend.ui.components.StatusTicks
import app.goldfishsend.ui.components.rememberQuery
import app.goldfishsend.ui.components.shortTime
import androidx.compose.foundation.clickable
import androidx.activity.compose.BackHandler
import android.view.inputmethod.EditorInfo
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.SearchOff
import androidx.compose.material3.CircularProgressIndicator
import app.goldfishsend.ui.components.MailboxWait
import app.goldfishsend.ui.components.SecureTextField
import app.goldfishsend.ui.components.rememberShowProgress
import app.goldfishsend.ui.components.rememberWork

enum class Tab { CHATS, SECURITY, SETTINGS }

@Composable
fun HomeScreen(
    s: Session,
    openChat: (Long) -> Unit,
    addContact: () -> Unit,
    openPassphrase: () -> Unit,
    newGroup: () -> Unit = {},
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
                    Tab.CHATS -> ChatList(s, openChat, addContact, newGroup)
                    Tab.SECURITY -> SecurityScreen(s, openPassphrase = openPassphrase, openChats = { tab = 0 })
                    Tab.SETTINGS -> SettingsScreen(s, openPassphrase)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChatList(s: Session, openChat: (Long) -> Unit, addContact: () -> Unit, newGroup: () -> Unit = {}) {
    val changes by s.db.changes.collectAsState()
    val allChats by produceState<List<ChatEntry>?>(null, s, changes) {
        value = ChatListPreload.take(s)?.await() ?: withContext(Dispatchers.IO) { runCatching { loadChats(s) }.getOrNull() }
    }
    // The first frame waits for the chats (see FirstFrame), and startup counts as complete once they are loaded.
    ContentReady(allChats != null)
    val revealed by s.hiddenRevealed.collectAsState()
    // Hidden chats stay out of the list until the hidden-chats PIN was entered in this session.
    val chats = remember(allChats, revealed) { allChats?.filter { !it.hidden || revealed } }
    var askHiddenPin by remember { mutableStateOf(false) }
    val focus = androidx.compose.ui.platform.LocalFocusManager.current
    val keyboard = androidx.compose.ui.platform.LocalSoftwareKeyboardController.current
    // Filters by name only: searching message text would mean decrypting every message.
    var searching by rememberSaveable { mutableStateOf(false) }
    var query by rememberSaveable { mutableStateOf("") }
    fun closeSearch() {
        // The field is an EditText: its keyboard doesn't go away with it by itself.
        focus.clearFocus()
        keyboard?.hide()
        searching = false
        query = ""
    }
    BackHandler(searching) { closeSearch() }
    val shown = remember(chats, query) {
        val q = query.trim()
        if (q.isEmpty()) chats else chats?.filter { it.name.contains(q, ignoreCase = true) }
    }
    val busy by Mailboxes.busy.collectAsState()
    val prefsVersion by Graph.prefs.version.collectAsState()
    val pushOk = prefsVersion.let { Graph.prefs.pushStatus == "ok" }
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        topBar = {
            LargeTopAppBar(
                // Long-pressing the title asks for the hidden-chats PIN. It always responds the same way, so it doesn't
                // reveal whether hidden chats exist.
                title = {
                    Text(
                        "Chats",
                        Modifier.combinedClickable(onClick = {}, onLongClick = { askHiddenPin = true }, indication = null,
                            interactionSource = remember { androidx.compose.foundation.interaction.MutableInteractionSource() }),
                    )
                },
                actions = {
                    if (!allChats.isNullOrEmpty()) {
                        IconButton(onClick = { if (searching) closeSearch() else searching = true }) {
                            Icon(if (searching) Icons.Rounded.SearchOff else Icons.Rounded.Search, if (searching) "Close search" else "Search chats")
                        }
                    }
                    IconButton(onClick = newGroup) { Icon(Icons.Rounded.GroupAdd, "New group") }
                },
                scrollBehavior = scroll,
            )
        },
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
            // First setup: the mailbox pool is being filled. The app is usable meanwhile; invites wait for the first one.
            val preparing = pushOk && busy && chats.isNullOrEmpty()
            MailboxWait(preparing, Modifier.padding(horizontal = 24.dp, vertical = 8.dp))
            StatusLine(revealed, "Showing hidden chats", action = "Hide") { s.hiddenRevealed.value = false }
            AnimatedVisibility(searching, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
                SecureTextField(
                    query, { query = it },
                    Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                    hint = "Search by name",
                    shape = RoundedCornerShape(28.dp),
                    imeAction = EditorInfo.IME_ACTION_SEARCH,
                    // Not again when coming back from a chat opened from the results.
                    requestFocus = query.isEmpty(),
                )
            }
            val list = shown
            if (list == null) {
                // The first frame waits up to a second for the chats; after that, say we're on it.
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    if (rememberShowProgress(true)) {
                        CircularProgressIndicator()
                    }
                }
            } else if (list.isEmpty() && query.isNotBlank()) {
                Text(
                    "No chats named “${query.trim()}”",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(32.dp),
                )
            } else if (list.isEmpty()) {
                EmptyChats(addContact)
            } else {
                // Not composed before the chats are loaded: rows arriving in an empty list would all fade in.
                LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 96.dp)) {
                    items(list, key = { it.id }, contentType = { "chat" }) { c ->
                        ChatRow(c, Modifier.animateItem()) {
                            // From a search: the search field's keyboard shouldn't follow into the chat.
                            focus.clearFocus()
                            keyboard?.hide()
                            openChat(c.id)
                        }
                    }
                }
            }
        }
    }
    if (askHiddenPin) {
        val work = rememberWork()
        PinEntryDialog(
            "Enter PIN", "", onDismiss = { askHiddenPin = false }, minLength = 4, confirm = false, busy = work.busy,
        ) { pin ->
            // The dialog closes the same way whether or not the PIN matched (or hidden chats exist).
            work.run {
                val ok = withContext(Dispatchers.Default) {
                    // The profile's own hidden-chats PIN: a decoy checks its own, at the same cost, never the real one.
                    s.secrets.isHiddenPin(pin).also { pin.fill('\u0000') }
                }
                if (ok) {
                    s.hiddenRevealed.value = true
                }
                askHiddenPin = false
            }
        }
    }
}

private fun loadChats(q: Session): List<ChatEntry> = traced("gf.chatList") {
    val groups = q.repo.groupRefs().associateBy { it.cid }
    q.repo.chatSummaries(System.currentTimeMillis()).map { c ->
        val ref = groups[c.contact.id]
        val sender = if (ref != null && !c.lastOutgoing && c.lastSender != null) {
            Groups.memberName(q, Groups.model(q, ref.cid), c.lastSender).name
        } else {
            null
        }
        ChatEntry.of(c, ref?.state, sender)
    }
}

/**
 * The chat list's first query, started as soon as the session opens at a cold start, while the activity is still being
 * created, instead of after the first composition. Used only if nothing in the database changed since it started.
 */
object ChatListPreload {
    private class Pending(val session: Session, val changes: Long, val result: Deferred<List<ChatEntry>?>)

    private var pending: Pending? = null

    /** The session whose chat list already loaded, so a late [start] doesn't leave decrypted previews in memory. */
    private var loaded = java.lang.ref.WeakReference<Session>(null)

    @Synchronized
    fun start(s: Session) {
        if (loaded.get() === s) {
            return
        }
        val changes = s.db.changes.value
        pending = Pending(s, changes, Graph.scope.async { runCatching { loadChats(s) }.getOrNull() })
    }

    @Synchronized
    internal fun take(s: Session): Deferred<List<ChatEntry>?>? {
        loaded = java.lang.ref.WeakReference(s)
        val p = pending ?: return null
        pending = null
        return p.result.takeIf { p.session === s && p.changes == s.db.changes.value }
    }
}

/**
 * A chat list row: what the row shows, and nothing else. Only immutable values (no Contact with its key arrays), so a
 * row whose chat didn't change skips recomposition when the list is re-queried, and the time label is formatted off
 * the main thread.
 */
internal data class ChatEntry(
    val id: Long,
    val name: String,
    val isGroup: Boolean,
    val verified: Boolean,
    val hasTimer: Boolean,
    val unread: Int,
    val hidden: Boolean,
    val unreachable: Boolean,
    val lastBody: String?,
    val lastOutgoing: Boolean,
    val lastStatus: Int,
    val time: String,
    val groupState: Int?,
    val sender: String?,
) {
    companion object {
        fun of(c: ChatSummary, groupState: Int?, sender: String?) = ChatEntry(
            id = c.contact.id,
            name = c.contact.name,
            isGroup = c.contact.isGroup,
            verified = c.contact.verified,
            hasTimer = c.contact.timerSecs > 0,
            unread = c.contact.unread,
            hidden = c.contact.hidden,
            unreachable = c.contact.unreachable,
            lastBody = c.lastBody,
            lastOutgoing = c.lastOutgoing,
            lastStatus = c.lastStatus,
            // The chat's latest activity, which orders the list (a system line can be newer than the previewed message).
            time = shortTime(maxOf(c.lastTs ?: 0L, c.contact.lastActivity)),
            groupState = groupState,
            sender = sender,
        )
    }
}

@Composable
private fun ChatRow(c: ChatEntry, modifier: Modifier, onClick: () -> Unit) {
    val unread = c.unread
    val invited = c.groupState == GroupModel.INVITED
    ListItem(
        modifier = modifier.clickable(onClick = onClick).padding(horizontal = 4.dp),
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        leadingContent = {
            if (c.isGroup) GroupAvatar(c.id, 52.dp) else Avatar(c.name, c.id, 52.dp)
        },
        headlineContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    c.name,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    fontWeight = if (unread > 0) FontWeight.SemiBold else FontWeight.Normal,
                    modifier = Modifier.weight(1f, fill = false),
                )
                if (c.verified && !c.isGroup) {
                    Spacer(Modifier.width(4.dp))
                    Icon(Icons.Rounded.Verified, "Verified", Modifier.size(16.dp), tint = MaterialTheme.colorScheme.primary)
                }
                if (c.hasTimer) {
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
                        invited -> "Invitation to join"
                        c.groupState == GroupModel.REMOVED -> "You were removed"
                        c.unreachable -> "Can't be reached right now"
                        c.lastBody != null && c.sender != null -> "${c.sender}: ${c.lastBody}"
                        c.lastBody != null -> c.lastBody
                        else -> "Say hi 👋"
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    color = when {
                        invited -> MaterialTheme.colorScheme.primary
                        unread > 0 -> MaterialTheme.colorScheme.onSurface
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        },
        trailingContent = {
            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    c.time,
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
