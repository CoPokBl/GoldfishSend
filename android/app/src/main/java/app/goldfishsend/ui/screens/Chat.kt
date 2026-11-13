package app.goldfishsend.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.DeleteForever
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material.icons.rounded.TimerOff
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SmallFloatingActionButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Messenger
import app.goldfishsend.core.Outbox
import app.goldfishsend.core.Session
import app.goldfishsend.core.TIMER_CHOICES
import app.goldfishsend.core.formatTimer
import app.goldfishsend.core.timerLabel
import app.goldfishsend.db.Message
import app.goldfishsend.db.MsgKind
import app.goldfishsend.db.MsgStatus
import app.goldfishsend.db.groupReaders
import app.goldfishsend.security.ClipboardGuard
import app.goldfishsend.ui.components.Avatar
import app.goldfishsend.ui.components.FieldKind
import app.goldfishsend.ui.components.SecureTextField
import app.goldfishsend.ui.components.StatusTicks
import app.goldfishsend.ui.components.countdown
import app.goldfishsend.ui.components.fullTime
import app.goldfishsend.ui.components.rememberQuery
import app.goldfishsend.ui.components.rememberTicker
import app.goldfishsend.ui.components.shortTime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChatScreen(s: Session, contactId: Long, back: () -> Unit, openInfo: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val contact by rememberQuery(s, contactId) { it.repo.contact(contactId) }
    // Tick once per second only while something on screen is counting down. Re-query (decrypt) only when a
    // message actually expires; between expiries the ticker just updates countdowns and hides expired rows.
    var hasTimers by remember { mutableStateOf(false) }
    val now by rememberTicker(hasTimers)
    var expiredEpoch by remember { mutableStateOf(0) }
    val loaded by rememberQuery(s, contactId, expiredEpoch) { it.repo.messages(contactId, System.currentTimeMillis()) }
    val messages = loaded?.filter { it.expiresAt == null || it.expiresAt > now }
    LaunchedEffect(loaded) {
        hasTimers = loaded?.any { it.expiresAt != null } == true
    }
    val expiredNow = loaded?.count { it.expiresAt != null && it.expiresAt <= now } ?: 0
    LaunchedEffect(expiredNow) {
        if (expiredNow > 0) {
            withContext(Dispatchers.IO) { runCatching { app.goldfishsend.core.Sweeper.sweep(s) } }
            expiredEpoch++
        }
    }
    var draft by remember { mutableStateOf("") }
    var selected by remember { mutableStateOf<Message?>(null) }
    var info by remember { mutableStateOf<Message?>(null) }
    // The text of a view-once message being shown. It exists only in memory: the message was deleted before display.
    var viewing by remember { mutableStateOf<String?>(null) }
    var timerMenu by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val atBottom by remember { derivedStateOf { listState.firstVisibleItemIndex <= 1 } }

    DisposableEffect(contactId) {
        Messenger.openChat.value = contactId
        onDispose { Messenger.openChat.value = null }
    }
    LaunchedEffect(messages?.firstOrNull()?.id) {
        withContext(Dispatchers.IO) { runCatching { Messenger.markChatRead(s, contactId) } }
        if (atBottom) {
            listState.animateScrollToItem(0)
        }
    }

    val c = contact
    val group by rememberQuery(s, contactId) { q -> if (q.repo.contact(contactId)?.isGroup == true) chatGroup(q, contactId) else null }
    val isGroup = c?.isGroup == true
    val g = group
    val snackbar = remember { androidx.compose.material3.SnackbarHostState() }
    val canSetTimer = !isGroup || (g != null && g.canEdit)
    Scaffold(
        snackbarHost = { androidx.compose.material3.SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                navigationIcon = { IconButton(onClick = back) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") } },
                title = {
                    Row(Modifier.clickable(onClick = openInfo), verticalAlignment = Alignment.CenterVertically) {
                        if (isGroup) {
                            app.goldfishsend.ui.components.GroupAvatar(contactId, 36.dp)
                        } else {
                            Avatar(c?.name ?: "", contactId, 36.dp)
                        }
                        Spacer(Modifier.width(12.dp))
                        Column {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(c?.name ?: "", maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.titleMedium)
                                if (c?.verified == true && !isGroup) {
                                    Spacer(Modifier.width(4.dp))
                                    Icon(Icons.Rounded.Verified, "Verified", Modifier.size(16.dp), tint = MaterialTheme.colorScheme.primary)
                                }
                            }
                            if (g != null) {
                                Text(
                                    g.subtitle + if ((c?.timerSecs ?: 0) > 0) " · disappearing: ${timerLabel(c!!.timerSecs).lowercase()}" else "",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            } else if (c != null && c.timerSecs > 0) {
                                Text(
                                    "Disappearing: ${timerLabel(c.timerSecs).lowercase()}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                },
                actions = {
                    if (canSetTimer) Box {
                        IconButton(onClick = { timerMenu = true }) {
                            Icon(if ((c?.timerSecs ?: 0) > 0) Icons.Rounded.Timer else Icons.Rounded.TimerOff, "Disappearing messages")
                        }
                        DropdownMenu(timerMenu, onDismissRequest = { timerMenu = false }) {
                            Text(
                                "Disappearing messages",
                                style = MaterialTheme.typography.labelLarge,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                            )
                            for (secs in TIMER_CHOICES) {
                                DropdownMenuItem(
                                    text = { Text(timerLabel(secs)) },
                                    trailingIcon = if (c?.timerSecs == secs) {
                                        { Icon(Icons.Rounded.Timer, null, tint = MaterialTheme.colorScheme.primary) }
                                    } else null,
                                    onClick = {
                                        timerMenu = false
                                        scope.launch(Dispatchers.IO) {
                                            if (isGroup) {
                                                app.goldfishsend.core.Groups.setTimer(s, contactId, secs)
                                            } else {
                                                Messenger.setTimer(s, contactId, secs)
                                            }
                                        }
                                    },
                                )
                            }
                        }
                    }
                },
            )
        },
        contentWindowInsets = androidx.compose.foundation.layout.WindowInsets(0),
    ) { pad ->
        Column(
            Modifier
                .padding(top = pad.calculateTopPadding())
                .fillMaxSize()
                .imePadding(),
        ) {
            if (isGroup) {
                // Groups: membership notices are system lines; delivery issues show per member in group info.
            } else if (c != null && c.pendingServerKey != null) {
                Banner("Can't verify ${c.name}'s server. Messages will wait until it's sorted out. Tap to review.", onClick = openInfo)
            } else if (c != null && c.unreachable) {
                Banner("This contact can't be reached right now. They may have removed you.")
            } else if (c != null && !c.verified) {
                Banner("Not verified. Compare safety numbers in contact info.", onClick = openInfo)
            }
            Box(Modifier.weight(1f)) {
                LazyColumn(
                    state = listState,
                    reverseLayout = true,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    items(messages.orEmpty(), key = { it.id }) { m ->
                        if (m.kind == MsgKind.SYSTEM) {
                            SystemChip(m.body, Modifier.animateItem())
                        } else {
                            Bubble(
                                m, now,
                                Modifier.animateItem(),
                                sender = if (g != null && !m.outgoing) m.senderKey?.let { k -> (g.names[k] ?: "Former member") to k } else null,
                                onLongPress = { selected = m },
                                onTap = {
                                    if (m.viewOnce && !m.outgoing) {
                                        scope.launch(Dispatchers.IO) {
                                            // Consumed (deleted, key shredded) *before* it's shown, so rotation, process
                                            // death, locking or dismissing can never show it twice.
                                            Messenger.consumeViewOnce(s, m.id)?.let { viewing = it }
                                        }
                                    } else if (m.status == MsgStatus.FAILED) {
                                        scope.launch(Dispatchers.IO) { Outbox.retry(s, m.id) }
                                    }
                                },
                            )
                        }
                    }
                }
                androidx.compose.animation.AnimatedVisibility(
                    !atBottom,
                    enter = scaleIn(),
                    exit = scaleOut(),
                    modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp),
                ) {
                    SmallFloatingActionButton(onClick = { scope.launch { listState.animateScrollToItem(0) } }) {
                        Icon(Icons.Rounded.KeyboardArrowDown, "Scroll to latest")
                    }
                }
            }
            when (g?.state) {
                app.goldfishsend.group.GroupModel.INVITED -> GroupInvitationBar(
                    s, contactId, g.inviter,
                    onError = { msg -> scope.launch { snackbar.showSnackbar(msg) } },
                    onDeclined = back,
                )
                app.goldfishsend.group.GroupModel.REMOVED, app.goldfishsend.group.GroupModel.LEFT -> Banner(
                    if (g.state == app.goldfishsend.group.GroupModel.REMOVED) {
                        "You were removed from this group, so you can't send messages here."
                    } else {
                        "You left this group, so you can't send messages here."
                    },
                )
                else -> Composer(draft, { draft = it }) {
                    val text = draft.trim()
                    if (text.isNotEmpty()) {
                        draft = ""
                        scope.launch {
                            withContext(Dispatchers.IO) { Messenger.sendText(s, contactId, text) }
                            listState.animateScrollToItem(0)
                        }
                    }
                }
            }
        }
    }

    selected?.let { m ->
        MessageActions(
            m,
            onDismiss = { selected = null },
            onCopy = { ClipboardGuard.copy(ctx, m.body) },
            onInfo = { info = m },
            onDeleteMe = { scope.launch(Dispatchers.IO) { Messenger.deleteForMe(s, m.id) } },
            onDeleteAll = { scope.launch(Dispatchers.IO) { Messenger.deleteForEveryone(s, m.id) } },
            onRetry = { scope.launch(Dispatchers.IO) { Outbox.retry(s, m.id) } },
        )
    }
    info?.let { m ->
        val readers by rememberQuery(s, m.id) { q -> if (isGroup && m.outgoing) q.repo.groupReaders(m.id).size else null }
        MessageInfo(m, readers) { info = null }
    }
    viewing?.let { body ->
        AlertDialog(
            onDismissRequest = { viewing = null },
            title = { Text("View once") },
            text = { Text(body, style = MaterialTheme.typography.bodyLarge) },
            confirmButton = { TextButton(onClick = { viewing = null }) { Text("Done") } },
        )
    }
}

@Composable
private fun Banner(text: String, onClick: (() -> Unit)? = null) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.fillMaxWidth().let { if (onClick != null) it.clickable(onClick = onClick) else it },
    ) {
        Text(
            text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
    }
}

@Composable
private fun SystemChip(text: String, modifier: Modifier) {
    Box(modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
        Surface(shape = RoundedCornerShape(50), color = MaterialTheme.colorScheme.surfaceContainerHigh) {
            Text(
                text,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
            )
        }
    }
}

/** A group as the chat screen needs it: our state, who invited us, member names and whether we may edit its info. */
private class ChatGroup(val state: Int, val inviter: String, val names: Map<String, String>, val canEdit: Boolean, val subtitle: String)

private fun chatGroup(s: Session, cid: Long): ChatGroup? {
    val m = app.goldfishsend.core.Groups.model(s, cid) ?: return null
    val r = m.roster?.roster ?: return null
    val me = app.goldfishsend.core.Groups.me(s)
    val names = r.members.associate { it.id to app.goldfishsend.core.Groups.memberName(s, m, it.id).name }
    val inviter = m.invitedBy?.let { app.goldfishsend.core.Groups.memberName(s, m, it).name } ?: "Someone"
    val active = r.members.count { it.role != app.goldfishsend.proto.Role.INVITED }
    return ChatGroup(m.state, inviter, names, app.goldfishsend.core.Groups.canEditInfo(m, me), "$active ${if (active == 1) "member" else "members"}")
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun Bubble(
    m: Message,
    now: Long,
    modifier: Modifier,
    sender: Pair<String, String>? = null,
    onLongPress: () -> Unit,
    onTap: () -> Unit,
) {
    val out = m.outgoing
    val bg = if (out) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceContainerHighest
    val fg = if (out) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface
    val meta = fg.copy(alpha = 0.72f)
    val shape = if (out) RoundedCornerShape(20.dp, 20.dp, 6.dp, 20.dp) else RoundedCornerShape(20.dp, 20.dp, 20.dp, 6.dp)
    Row(modifier.fillMaxWidth(), horizontalArrangement = if (out) Arrangement.End else Arrangement.Start) {
        Column(
            Modifier
                .widthIn(max = 320.dp)
                .background(bg, shape)
                .combinedClickable(onClick = onTap, onLongClick = onLongPress)
                .padding(start = 14.dp, end = 12.dp, top = 9.dp, bottom = 6.dp),
        ) {
            sender?.let { (name, key) ->
                Text(
                    name,
                    style = MaterialTheme.typography.labelMedium,
                    color = app.goldfishsend.ui.components.memberColor(key),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (m.viewOnce && !out) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Rounded.Visibility, null, Modifier.size(18.dp), tint = fg)
                    Spacer(Modifier.width(8.dp))
                    Text("View-once message. Tap to view", color = fg, style = MaterialTheme.typography.bodyLarge)
                }
            } else {
                Text(m.body, color = fg, style = MaterialTheme.typography.bodyLarge)
            }
            Row(
                Modifier.align(Alignment.End).padding(top = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                m.expiresAt?.let { exp ->
                    Icon(Icons.Rounded.Timer, "Disappears", Modifier.size(12.dp), tint = meta)
                    Text(countdown(exp - now), style = MaterialTheme.typography.labelSmall, color = meta)
                }
                Text(shortTime(m.ts), style = MaterialTheme.typography.labelSmall, color = meta)
                if (out) {
                    StatusTicks(m.status, meta)
                }
            }
            if (out && m.status == MsgStatus.FAILED) {
                Text("Not sent. Tap to retry", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.errorContainer)
            }
        }
    }
}

@Composable
private fun Composer(draft: String, onDraft: (String) -> Unit, onSend: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .padding(start = 12.dp, end = 8.dp, top = 6.dp, bottom = 8.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        SecureTextField(
            draft, onDraft,
            Modifier.weight(1f),
            hint = "Message",
            kind = FieldKind.MESSAGE,
            maxLines = 6,
            shape = RoundedCornerShape(26.dp),
        )
        Spacer(Modifier.width(8.dp))
        AnimatedVisibility(true) {
            FilledIconButton(onClick = onSend, enabled = draft.isNotBlank(), modifier = Modifier.size(52.dp)) {
                Icon(Icons.AutoMirrored.Rounded.Send, "Send")
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MessageActions(
    m: Message,
    onDismiss: () -> Unit,
    onCopy: () -> Unit,
    onInfo: () -> Unit,
    onDeleteMe: () -> Unit,
    onDeleteAll: () -> Unit,
    onRetry: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        fun act(f: () -> Unit) = {
            onDismiss()
            f()
        }
        val colors = ListItemDefaults.colors(containerColor = Color.Transparent)
        Column(Modifier.padding(bottom = 24.dp)) {
            if (!m.viewOnce) {
                ListItem(
                    headlineContent = { Text("Copy") }, leadingContent = { Icon(Icons.Rounded.ContentCopy, null) },
                    modifier = Modifier.clickable(onClick = act(onCopy)), colors = colors,
                )
            }
            if (m.status == MsgStatus.FAILED && m.outgoing) {
                ListItem(
                    headlineContent = { Text("Retry") }, leadingContent = { Icon(Icons.Rounded.Refresh, null) },
                    modifier = Modifier.clickable(onClick = act(onRetry)), colors = colors,
                )
            }
            ListItem(
                headlineContent = { Text("Info") }, leadingContent = { Icon(Icons.Rounded.Info, null) },
                modifier = Modifier.clickable(onClick = act(onInfo)), colors = colors,
            )
            HorizontalDivider(Modifier.padding(vertical = 4.dp))
            ListItem(
                headlineContent = { Text("Delete for me") }, leadingContent = { Icon(Icons.Rounded.Delete, null) },
                modifier = Modifier.clickable(onClick = act(onDeleteMe)), colors = colors,
            )
            if (m.outgoing) {
                ListItem(
                    headlineContent = { Text("Delete for everyone", color = MaterialTheme.colorScheme.error) },
                    supportingContent = { Text("Their app will delete it too, if it's unmodified") },
                    leadingContent = { Icon(Icons.Rounded.DeleteForever, null, tint = MaterialTheme.colorScheme.error) },
                    modifier = Modifier.clickable(onClick = act(onDeleteAll)), colors = colors,
                )
            }
        }
    }
}

@Composable
private fun MessageInfo(m: Message, readers: Int? = null, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Message info") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                InfoLine(if (m.outgoing) "Sent" else "Sent by them", fullTime(m.ts))
                m.receivedAt?.let { InfoLine("Received", fullTime(it)) }
                m.readAt?.let { InfoLine("Read", fullTime(it)) }
                if (m.outgoing) {
                    InfoLine(
                        "Status",
                        when (m.status) {
                            MsgStatus.QUEUED -> "Sending"
                            MsgStatus.SENT -> "Sent"
                            MsgStatus.DELIVERED -> "Delivered"
                            MsgStatus.READ -> "Read"
                            else -> "Not sent"
                        },
                    )
                    if (readers != null && m.recipients > 0) {
                        InfoLine("Read by", "$readers of ${m.recipients}")
                    }
                }
                if (m.expSecs > 0) {
                    InfoLine("Disappears", m.expiresAt?.let { fullTime(it) } ?: "${formatTimer(m.expSecs)} after reading")
                }
                InfoLine("Encryption", "End-to-end (Signal protocol, post-quantum)")
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}

@Composable
private fun InfoLine(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
