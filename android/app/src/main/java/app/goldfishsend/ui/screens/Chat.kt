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
import app.goldfishsend.core.traced
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
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.gestures.scrollBy
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.material.icons.rounded.CloudOff
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.graphics.graphicsLayer
import app.goldfishsend.ui.ChatRow
import app.goldfishsend.ui.ChatRows
import app.goldfishsend.ui.DayRow
import app.goldfishsend.ui.MessageRow
import app.goldfishsend.ui.UnreadRow
import app.goldfishsend.ui.components.ButtonKind
import app.goldfishsend.ui.components.ProgressButton
import app.goldfishsend.ui.components.Spinner
import app.goldfishsend.ui.components.clockTime
import app.goldfishsend.ui.components.dayLabels
import app.goldfishsend.ui.components.localDay
import app.goldfishsend.ui.components.rememberShowProgress
import app.goldfishsend.ui.components.rememberWork
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A chat's messages (newest first) and which outgoing ones are waiting to be retried. */
private class ChatData(val messages: List<Message>, val waiting: Set<String>)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChatScreen(s: Session, contactId: Long, back: () -> Unit, openInfo: () -> Unit) {
    val focus = androidx.compose.ui.platform.LocalFocusManager.current
    val keyboard = androidx.compose.ui.platform.LocalSoftwareKeyboardController.current
    // Leaving for contact or group info: don't carry the composer's keyboard onto a screen with no text field.
    val showInfo: () -> Unit = {
        focus.clearFocus()
        keyboard?.hide()
        openInfo()
    }
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val contact by rememberQuery(s, contactId) { it.repo.contact(contactId) }
    // Tick once per second only while something on screen is counting down. Re-query (decrypt) only when a
    // message actually expires; between expiries the ticker just updates countdowns and hides expired rows.
    var hasTimers by remember { mutableStateOf(false) }
    val now by rememberTicker(hasTimers)
    var expiredEpoch by remember { mutableStateOf(0) }
    // Bodies already decrypted for this chat: a status change or a new message then costs one decryption, not 500.
    val bodies = remember(contactId) { java.util.concurrent.atomic.AtomicReference<Map<String, String>>(emptyMap()) }
    val loaded by rememberQuery(s, contactId, expiredEpoch) { q ->
        traced("gf.messages") {
            val list = q.repo.messages(contactId, System.currentTimeMillis(), known = bodies.get())
            bodies.set(list.associate { it.id to it.body })
            ChatData(list, q.repo.waitingMessageIds(contactId))
        }
    }
    LaunchedEffect(loaded) {
        hasTimers = loaded?.messages?.any { it.expiresAt != null } == true
    }
    val expiredNow = remember(loaded, now) { loaded?.messages?.count { it.expiresAt != null && it.expiresAt <= now } ?: 0 }
    // Rebuilt when a message expires, not on every tick: countdowns get the clock separately.
    val messages = remember(loaded, expiredNow) { loaded?.messages?.filter { it.expiresAt == null || it.expiresAt > now } }
    LaunchedEffect(expiredNow) {
        if (expiredNow > 0) {
            withContext(Dispatchers.IO) { runCatching { app.goldfishsend.core.Sweeper.sweep(s) } }
            expiredEpoch++
        }
    }
    // Where "New messages" goes: the oldest unread message when the chat opened. Taken from the first load, before the
    // chat is marked read.
    val firstUnread = remember(messages != null) { messages?.let(ChatRows::firstUnread) }
    // Gone once we reply.
    var dividerCleared by remember { mutableStateOf(false) }
    val unreadFrom = if (dividerCleared) null else firstUnread
    // Read only inside the composer, so typing doesn't recompose the whole chat.
    val draft = remember { mutableStateOf("") }
    // Set when we send, so the list follows our new message even if we were scrolled up.
    var followSent by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<Message?>(null) }
    var info by remember { mutableStateOf<Message?>(null) }
    // The text of a view-once message being shown. It exists only in memory: the message was deleted before display.
    var viewing by remember { mutableStateOf<String?>(null) }
    var timerMenu by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val atBottom by remember { derivedStateOf { listState.firstVisibleItemIndex <= 1 } }

    val c = contact
    // Sending to the contact is paused until the user reviews their new safety number or server key.
    val paused = c != null && !c.isGroup && (c.pendingIdentity != null || c.pendingServerKey != null)
    val waiting = loaded?.waiting.orEmpty()
    val today = remember(loaded) { localDay(System.currentTimeMillis()) }
    // Bumped when a message has been "sending" for too long, to show it as waiting.
    var staleCheck by remember { mutableStateOf(0) }
    val rows = remember(messages, unreadFrom, waiting, paused, staleCheck) {
        val staleBefore = System.currentTimeMillis() - ChatRows.SENDING_MS
        messages?.let { ChatRows.build(it, unreadFrom, waiting, paused, ::localDay, staleBefore) }
    }
    val anyWaiting = remember(rows) { rows.orEmpty().any { it is MessageRow && it.waiting } }
    LaunchedEffect(rows) {
        val sending = rows?.mapNotNull { r -> (r as? MessageRow)?.takeIf { it.m.outgoing && it.m.status == MsgStatus.QUEUED && !it.waiting }?.m?.ts }
        val oldest = sending?.minOrNull() ?: return@LaunchedEffect
        delay((oldest + ChatRows.SENDING_MS - System.currentTimeMillis()).coerceAtLeast(0) + 50)
        staleCheck++
    }

    // The newest message the user has had on screen. Incoming messages after it count on the "scroll to latest" button.
    var seenUpTo by remember { mutableStateOf<Long?>(null) }
    var positioned by remember { mutableStateOf(false) }
    LaunchedEffect(rows, positioned) {
        val r = rows ?: return@LaunchedEffect
        if (!positioned) {
            return@LaunchedEffect
        }
        snapshotFlow { listState.firstVisibleItemIndex }.collect { first ->
            val newest = (first until r.size).firstNotNullOfOrNull { (r[it] as? MessageRow)?.m?.ts } ?: return@collect
            val seen = seenUpTo
            if (seen == null || newest > seen) {
                seenUpTo = newest
            }
        }
    }
    val unseen = remember(messages, seenUpTo) {
        val seen = seenUpTo
        if (messages == null || seen == null) 0 else ChatRows.unseen(messages, seen)
    }

    DisposableEffect(contactId) {
        Messenger.openChat.value = contactId
        onDispose { Messenger.openChat.value = null }
    }
    // Opened with unread messages: start at "New messages" rather than at the bottom, unless they all fit on screen.
    LaunchedEffect(rows != null) {
        val r = rows ?: return@LaunchedEffect
        val divider = r.indexOfFirst { it is UnreadRow }
        if (divider > 0) {
            // With the day's separator above it, if it's the day's first unread message.
            val top = if (r.getOrNull(divider + 1) is DayRow) divider + 1 else divider
            listState.scrollToItem(top)
            val info = listState.layoutInfo
            val shown = info.visibleItemsInfo.filter { it.index in divider..top }.sumOf { it.size }
            val room = info.viewportEndOffset - info.viewportStartOffset - shown - info.afterContentPadding - info.beforeContentPadding
            if (room > 0) {
                listState.scrollBy(-room.toFloat())
            }
        }
        positioned = true
    }
    // Marks the chat read once the user has seen its newest message (not while they're scrolled up reading older ones).
    LaunchedEffect(messages?.firstOrNull()?.id, unseen == 0, positioned) {
        if (messages == null || !positioned) {
            return@LaunchedEffect
        }
        if (unseen == 0) {
            withContext(Dispatchers.IO) { runCatching { Messenger.markChatRead(s, contactId) } }
        }
        if (atBottom || followSent) {
            followSent = false
            listState.animateScrollToItem(0)
        }
    }

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
                    Row(Modifier.clickable(onClick = showInfo), verticalAlignment = Alignment.CenterVertically) {
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
                Banner("Can't verify ${c.name}'s server. Messages will wait until it's sorted out. Tap to review.", onClick = showInfo)
            } else if (c != null && c.pendingIdentity != null) {
                Banner("${c.name}'s safety number changed. Messages are paused until you review it. Tap to review.", onClick = showInfo)
            } else if (c != null && c.unreachable) {
                Banner("This contact can't be reached right now. They may have removed you.")
            } else if (c != null && !c.verified) {
                Banner("Not verified. Compare safety numbers in contact info.", onClick = showInfo)
            }
            Box(Modifier.weight(1f)) {
                val r = rows
                // Not composed before the messages are loaded: bubbles arriving in an empty list would all fade in.
                if (r != null) LazyColumn(
                    state = listState,
                    reverseLayout = true,
                    // Hidden for the frame or two it takes to move to "New messages", so the chat doesn't jump.
                    modifier = Modifier.fillMaxSize().graphicsLayer { alpha = if (positioned) 1f else 0f },
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    items(r, key = { it.key }, contentType = { rowType(it) }) { row ->
                        when (row) {
                            is DayRow -> DaySeparator(row.day, today, Modifier.animateItem())
                            is UnreadRow -> NewMessagesDivider(Modifier.animateItem())
                            is MessageRow -> {
                                val m = row.m
                                if (m.kind == MsgKind.SYSTEM) {
                                    SystemChip(m.body, Modifier.animateItem())
                                } else {
                                    Bubble(
                                        // Only counting-down bubbles take the ticking clock, so the others skip recomposition every second.
                                        m, if (m.expiresAt != null) now else 0L,
                                        Modifier.animateItem(),
                                        waiting = row.waiting,
                                        sender = if (g != null && !m.outgoing) m.senderKey?.let { k -> (g.names[k] ?: "Former member") to k } else null,
                                        onLongPress = { selected = m },
                                        onTap = {
                                            if (m.viewOnce && !m.outgoing) {
                                                scope.launch(Dispatchers.IO) {
                                                    // Consumed (deleted, key shredded) *before* it's shown, so rotation, process
                                                    // death, locking or dismissing can never show it twice.
                                                    Messenger.consumeViewOnce(s, m.id)?.let { viewing = it }
                                                }
                                            } else if (m.status == MsgStatus.FAILED && Outbox.canRetry(m.ts)) {
                                                scope.launch(Dispatchers.IO) { Outbox.retry(s, m.id) }
                                            }
                                        },
                                    )
                                }
                            }
                        }
                    }
                } else {
                    // Decrypting a long chat can take a moment on a slow phone.
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        if (rememberShowProgress(true)) {
                            CircularProgressIndicator()
                        }
                    }
                }
                if (r != null) {
                    FloatingDay(listState, r, today, Modifier.align(Alignment.TopCenter).padding(top = 8.dp))
                }
                androidx.compose.animation.AnimatedVisibility(
                    !atBottom || unseen > 0,
                    enter = scaleIn(),
                    exit = scaleOut(),
                    modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp),
                ) {
                    BadgedBox(
                        badge = {
                            if (unseen > 0) {
                                Badge(containerColor = MaterialTheme.colorScheme.primary) { Text(if (unseen > 99) "99+" else "$unseen") }
                            }
                        },
                    ) {
                        SmallFloatingActionButton(onClick = {
                            scope.launch {
                                // Far up: jump most of the way, then glide the rest, instead of animating through everything.
                                if (listState.firstVisibleItemIndex > 12) {
                                    listState.scrollToItem(12)
                                }
                                listState.animateScrollToItem(0)
                            }
                        }) {
                            Icon(Icons.Rounded.KeyboardArrowDown, if (unseen > 0) "Scroll to latest, $unseen new" else "Scroll to latest")
                        }
                    }
                }
            }
            if (!paused && anyWaiting) {
                WaitingBar(s, contactId)
            }
            when (g?.state) {
                app.goldfishsend.group.GroupModel.INVITED -> GroupInvitationBar(
                    s, contactId, c?.name ?: "the group", g.inviter,
                    onDeclined = back,
                )
                app.goldfishsend.group.GroupModel.REMOVED, app.goldfishsend.group.GroupModel.LEFT -> Banner(
                    if (g.state == app.goldfishsend.group.GroupModel.REMOVED) {
                        "You were removed from this group, so you can't send messages here."
                    } else {
                        "You left this group, so you can't send messages here."
                    },
                )
                // Joined, but not taken in yet.
                else -> if (g != null && !g.admitted) {
                    WaitingToBeLetIn(s, contactId, g.sendAgainAt)
                } else Composer(draft) { text ->
                    followSent = true
                    dividerCleared = true
                    scope.launch {
                        // Far up in the history: jump down now, then the new message animates in once it's stored.
                        if (listState.firstVisibleItemIndex > 20) {
                            listState.scrollToItem(0)
                        }
                        withContext(Dispatchers.IO) { Messenger.sendText(s, contactId, text) }
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

private fun rowType(r: ChatRow): Int = when (r) {
    is MessageRow -> r.m.kind
    is DayRow -> 10
    is UnreadRow -> 11
}

@Composable
private fun DaySeparator(day: Long, today: Long, modifier: Modifier) {
    val label = remember(day, today) { dayLabels().label(day, today) }
    Box(modifier.fillMaxWidth().padding(top = 12.dp, bottom = 6.dp), contentAlignment = Alignment.Center) {
        DayChip(label)
    }
}

@Composable
private fun DayChip(label: String) {
    Surface(shape = RoundedCornerShape(50), color = MaterialTheme.colorScheme.surfaceContainerHigh, shadowElevation = 0.dp) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
        )
    }
}

/** While scrolling, the day of the messages at the top of the screen, so you know where you are in a long chat. */
@Composable
private fun FloatingDay(listState: LazyListState, rows: List<ChatRow>, today: Long, modifier: Modifier) {
    // The topmost visible row (the list is reversed). Recomposes only when it moves to another day.
    val topDay by remember(rows) {
        derivedStateOf {
            val top = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: return@derivedStateOf null
            // A separator at the top already says it.
            rows.getOrNull(top)?.takeIf { it !is DayRow }?.day
        }
    }
    val scrolling = listState.isScrollInProgress
    val away by remember { derivedStateOf { listState.firstVisibleItemIndex > 0 } }
    var show by remember { mutableStateOf(false) }
    LaunchedEffect(scrolling) {
        if (scrolling) {
            show = true
        } else {
            delay(1200)
            show = false
        }
    }
    val day = topDay
    // Keeps the label while the chip fades out.
    val last = remember { longArrayOf(Long.MIN_VALUE) }
    if (day != null) {
        last[0] = day
    }
    androidx.compose.animation.AnimatedVisibility(show && day != null && away, modifier, enter = fadeIn(), exit = fadeOut()) {
        last[0].takeIf { it != Long.MIN_VALUE }?.let { d ->
            val label = remember(d, today) { dayLabels().label(d, today) }
            Surface(shape = RoundedCornerShape(50), color = MaterialTheme.colorScheme.surfaceContainerHighest, shadowElevation = 2.dp) {
                Text(
                    label,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                )
            }
        }
    }
}

@Composable
private fun NewMessagesDivider(modifier: Modifier) {
    Row(modifier.fillMaxWidth().padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        HorizontalDivider(Modifier.weight(1f), color = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f))
        Text(
            "New messages",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(horizontal = 12.dp),
        )
        HorizontalDivider(Modifier.weight(1f), color = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f))
    }
}

/** Messages are waiting in the outbox: why, and a way to try again now. */
@Composable
private fun WaitingBar(s: Session, contactId: Long) {
    val online = rememberOnline()
    val work = rememberWork()
    Surface(color = MaterialTheme.colorScheme.surfaceContainerHigh, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(start = 16.dp, end = 8.dp, top = 2.dp, bottom = 2.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Rounded.CloudOff, null, Modifier.size(18.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.width(12.dp))
            Text(
                if (online) {
                    "Can't reach the server. Messages will send when it can be reached."
                } else {
                    "Not connected. Messages will send when you're back online."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            ProgressButton(
                onClick = { work.run { withContext(Dispatchers.IO) { runCatching { Outbox.retryNow(s, contactId) } } } },
                busy = work.busy,
                kind = ButtonKind.TEXT,
            ) { Text("Retry") }
        }
    }
}

/**
 * Joined a group, and waiting for its owner to let us in. Our request (or the owner's answer) may have been lost, and
 * nothing sends it again by itself: the user can, at most once every few minutes ([sendAgainAt]).
 */
@Composable
private fun WaitingToBeLetIn(s: Session, contactId: Long, sendAgainAt: Long?) {
    val work = rememberWork()
    var failed by remember { mutableStateOf(false) }
    val now by rememberTicker(sendAgainAt != null, periodMs = 10_000)
    val wait = (sendAgainAt ?: 0) - now
    Surface(color = MaterialTheme.colorScheme.surfaceContainerHigh, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 2.dp)) {
            Text(
                "Waiting for the group's owner to let you in. You can send messages once they have.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(end = 8.dp),
            )
            if (sendAgainAt != null) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        when {
                            failed -> "Couldn't send your request. Try again later."
                            wait > 0 -> "Request sent. You can send it again in ${minutesText(wait)}."
                            else -> "Still waiting? Send your request again."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    ProgressButton(
                        onClick = {
                            work.run {
                                failed = !withContext(Dispatchers.IO) {
                                    runCatching { app.goldfishsend.core.Groups.sendAgain(s, contactId) }.getOrDefault(false)
                                }
                            }
                        },
                        busy = work.busy,
                        enabled = wait <= 0,
                        kind = ButtonKind.TEXT,
                    ) { Text("Send again") }
                }
            }
        }
    }
}

/** A wait in whole minutes, rounded up: "a minute", "4 minutes". */
private fun minutesText(ms: Long): String {
    val mins = (ms + 59_999) / 60_000
    return if (mins <= 1) "a minute" else "$mins minutes"
}

/** Whether the phone has a network right now (ACCESS_NETWORK_STATE comes with WorkManager). */
@Composable
private fun rememberOnline(): Boolean {
    val ctx = LocalContext.current
    val cm = remember { ctx.getSystemService(android.net.ConnectivityManager::class.java) }
    var online by remember { mutableStateOf(runCatching { cm.activeNetwork != null }.getOrDefault(true)) }
    DisposableEffect(cm) {
        val cb = object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) {
                online = true
            }

            // The default network went away; a replacement arrives through onAvailable.
            override fun onLost(network: android.net.Network) {
                online = false
            }
        }
        val ok = runCatching { cm.registerDefaultNetworkCallback(cb) }.isSuccess
        onDispose {
            if (ok) {
                runCatching { cm.unregisterNetworkCallback(cb) }
            }
        }
    }
    return online
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
private class ChatGroup(
    val state: Int,
    val inviter: String,
    val names: Map<String, String>,
    val canEdit: Boolean,
    val subtitle: String,
    val admitted: Boolean,
    /** Waiting to be let in: when "Send again" is allowed (null: nothing to send again). */
    val sendAgainAt: Long?,
)

private fun chatGroup(s: Session, cid: Long): ChatGroup? {
    val m = app.goldfishsend.core.Groups.model(s, cid) ?: return null
    val r = m.view() ?: return null
    val me = app.goldfishsend.core.Groups.me(s)
    // Members now, plus anyone who sent a message here and has since left (their name is remembered from their card).
    val senders = s.repo.db.query("SELECT DISTINCT sender_key FROM messages WHERE contact_id = ? AND sender_key IS NOT NULL", cid) { it.getString(0) }
    // Named together, so that names that look alike are told apart; a name someone chose themselves is marked as theirs.
    val ids = (r.members.map { it.id } + senders + listOfNotNull(m.invitedBy)).toSet()
    val names = app.goldfishsend.core.Groups.memberNames(s, m, ids).mapValues { it.value.label }
    val inviter = m.invitedBy?.let { names[it] } ?: "Someone"
    val active = r.members.count { it.role != app.goldfishsend.proto.Role.INVITED }
    val invited = r.members.size - active
    val count = "$active ${if (active == 1) "member" else "members"}" + if (invited > 0) ", $invited invited" else ""
    return ChatGroup(
        m.state, inviter, names, app.goldfishsend.core.Groups.canEditInfo(m, me), count, app.goldfishsend.group.GroupEngine.admitted(m, me),
        app.goldfishsend.group.GroupEngine.sendAgainAt(m, me),
    )
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun Bubble(
    m: Message,
    now: Long,
    modifier: Modifier,
    waiting: Boolean = false,
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
                Text(clockTime(m.ts), style = MaterialTheme.typography.labelSmall, color = meta)
                if (out && m.status == MsgStatus.QUEUED && !waiting) {
                    // On its way to the server.
                    Spinner(Modifier.padding(1.dp).size(13.dp), color = meta, description = "Sending")
                } else if (out) {
                    StatusTicks(m.status, meta)
                }
            }
            if (out && waiting) {
                Text("Waiting to send", style = MaterialTheme.typography.labelSmall, color = meta, modifier = Modifier.align(Alignment.End))
            } else if (out && m.status == MsgStatus.FAILED) {
                // Too old to send again (Outbox.canRetry): it can still be copied into a new message.
                Text(if (Outbox.canRetry(m.ts)) "Not sent. Tap to retry" else "Not sent", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.errorContainer)
            }
        }
    }
}

@Composable
private fun Composer(draft: androidx.compose.runtime.MutableState<String>, onSend: (String) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .padding(start = 12.dp, end = 8.dp, top = 6.dp, bottom = 8.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        SecureTextField(
            draft.value, { draft.value = it },
            Modifier.weight(1f),
            hint = "Message",
            kind = FieldKind.MESSAGE,
            maxLines = 6,
            shape = RoundedCornerShape(26.dp),
        )
        Spacer(Modifier.width(8.dp))
        AnimatedVisibility(true) {
            FilledIconButton(
                onClick = {
                    val text = draft.value.trim()
                    if (text.isNotEmpty()) {
                        draft.value = ""
                        onSend(text)
                    }
                },
                enabled = draft.value.isNotBlank(),
                modifier = Modifier.size(52.dp),
            ) {
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
            if (m.status == MsgStatus.FAILED && m.outgoing && Outbox.canRetry(m.ts)) {
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
