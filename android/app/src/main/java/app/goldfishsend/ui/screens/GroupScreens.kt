package app.goldfishsend.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.Logout
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.DeleteForever
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.PersonAdd
import androidx.compose.material.icons.rounded.PersonRemove
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.goldfishsend.core.Graph
import app.goldfishsend.core.GroupException
import app.goldfishsend.core.Groups
import app.goldfishsend.core.Messenger
import app.goldfishsend.core.Notifier
import app.goldfishsend.core.Session
import app.goldfishsend.core.TIMER_CHOICES
import app.goldfishsend.core.timerLabel
import app.goldfishsend.db.Contact
import app.goldfishsend.db.memberRoutes
import app.goldfishsend.group.GroupModel
import app.goldfishsend.proto.B64
import app.goldfishsend.proto.Role
import app.goldfishsend.proto.RosterRules
import app.goldfishsend.ui.components.Avatar
import app.goldfishsend.ui.components.ChoiceDialog
import app.goldfishsend.ui.components.ConfirmDialog
import app.goldfishsend.ui.components.FieldKind
import app.goldfishsend.ui.components.GroupAvatar
import app.goldfishsend.ui.components.SecureTextField
import app.goldfishsend.ui.components.SettingRow
import app.goldfishsend.ui.components.SwitchRow
import app.goldfishsend.ui.components.blockWhenObscured
import app.goldfishsend.ui.components.memberColor
import app.goldfishsend.ui.components.rememberQuery
import app.goldfishsend.ui.components.BusyDialog
import app.goldfishsend.ui.components.ButtonKind
import app.goldfishsend.ui.components.ProgressButton
import app.goldfishsend.ui.components.ProgressRow
import app.goldfishsend.ui.components.TopProgressBar
import app.goldfishsend.ui.components.rememberWork
import app.goldfishsend.core.Mailboxes
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.collectAsState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Contacts who can be invited to a group: people we've exchanged keys with and whose safety number isn't in review. */
internal fun invitable(s: Session): List<Contact> =
    s.repo.people().filter { it.identityKey != null && it.pendingIdentity == null && it.ready }

/** "New group": a name and some contacts. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NewGroupScreen(s: Session, back: () -> Unit, openChat: (Long) -> Unit) {
    val scope = rememberCoroutineScope()
    val contacts by rememberQuery(s) { invitable(it) }
    var name by remember { mutableStateOf("") }
    val picked = remember { mutableStateListOf<Long>() }
    var busy by remember { mutableStateOf(false) }
    val snackbar = remember { SnackbarHostState() }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("New group") },
                navigationIcon = { IconButton(onClick = back) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().imePadding()) {
            Row(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                GroupAvatar(name.hashCode().toLong(), 56.dp)
                Spacer(Modifier.width(16.dp))
                SecureTextField(name, { name = it.take(64) }, Modifier.weight(1f), hint = "Group name", kind = FieldKind.TEXT)
            }
            Text(
                "Members",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(start = 20.dp, top = 12.dp, bottom = 4.dp),
            )
            val list = contacts.orEmpty()
            if (contacts != null && list.isEmpty()) {
                Text(
                    "Add some contacts first. Only people you've already chatted with can be invited.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(20.dp),
                )
            }
            LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(bottom = 16.dp)) {
                items(list, key = { it.id }) { c ->
                    val on = c.id in picked
                    ListItem(
                        headlineContent = { Text(c.name) },
                        leadingContent = { Avatar(c.name, c.id, 40.dp) },
                        trailingContent = { Checkbox(on, onCheckedChange = null) },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier.clickable {
                            if (on) {
                                picked.remove(c.id)
                            } else if (picked.size + 1 < RosterRules.MAX_MEMBERS) {
                                picked.add(c.id)
                            }
                        },
                    )
                }
            }
            val making by Mailboxes.progress.collectAsState()
            ProgressRow(
                busy, "Creating the group…", Modifier.padding(horizontal = 20.dp),
                hint = if (making != null) "Setting up the group's private inbox. This can take up to a minute." else null,
            )
            ProgressButton(
                onClick = {
                    busy = true
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { runCatching { Groups.create(s, name, picked.toList()) } }
                        busy = false
                        r.onSuccess(openChat).onFailure {
                            snackbar.showSnackbar(groupError(it, "Couldn't create the group. Try again."))
                        }
                    }
                },
                busy = busy,
                enabled = name.isNotBlank() && picked.isNotEmpty(),
                modifier = Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).height(52.dp),
            ) {
                Text(if (picked.isEmpty()) "Create group" else "Create group with ${picked.size}")
            }
        }
    }
}

/** One row of the member list, ready to show. */
private data class MemberRow(
    val id: String,
    val name: String,
    val role: String,
    val isMe: Boolean,
    val isContact: Boolean,
    val verified: Boolean,
    val serverIssue: Boolean,
)

private class GroupInfo(val model: GroupModel, val me: String, val members: List<MemberRow>)

private fun loadInfo(s: Session, cid: Long): GroupInfo? {
    val m = Groups.model(s, cid) ?: return null
    val me = Groups.me(s)
    val routes = s.repo.memberRoutes(cid)
    val roster = m.roster?.roster ?: return null
    val rows = roster.members.map { rm ->
        val n = Groups.memberName(s, m, rm.id)
        MemberRow(
            rm.id, n.name, rm.role, rm.id == me, n.isContact, n.verified,
            routes[rm.id]?.let { it.pendingServerKey != null || it.unreachable } == true,
        )
    }.sortedWith(compareBy<MemberRow>({ !it.isMe }, { it.role != Role.ADMIN }, { it.role == Role.INVITED }, { it.name.lowercase() }))
    return GroupInfo(m, me, rows)
}

/** Group info: members and roles, settings, leave. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupInfoScreen(s: Session, cid: Long, back: () -> Unit, onDeleted: () -> Unit) {
    val scope = rememberCoroutineScope()
    val contact by rememberQuery(s, cid) { it.repo.contact(cid) }
    val info by rememberQuery(s, cid) { loadInfo(it, cid) }
    val snackbar = remember { SnackbarHostState() }
    var rename by remember { mutableStateOf(false) }
    var timer by remember { mutableStateOf(false) }
    var adding by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<MemberRow?>(null) }
    var safetyFor by remember { mutableStateOf<MemberRow?>(null) }
    var confirmRemove by remember { mutableStateOf<MemberRow?>(null) }
    var confirmLeave by remember { mutableStateOf(false) }
    var promoteFirst by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var confirmClear by remember { mutableStateOf(false) }
    val erasing = rememberWork()
    val deleting = rememberWork()
    val c = contact ?: return
    val g = info ?: return
    val m = g.model
    val r = m.roster?.roster
    val joined = m.state == GroupModel.JOINED
    val amAdmin = joined && r?.isAdmin(g.me) == true
    val canEdit = Groups.canEditInfo(m, g.me)

    val work = rememberWork()
    var doing by remember { mutableStateOf("") }

    fun act(what: String, block: suspend () -> Unit) {
        work.run {
            doing = what
            val res = withContext(Dispatchers.IO) { runCatching { block() } }
            res.onFailure { snackbar.showSnackbar(groupError(it, "Something went wrong. Try again.")) }
        }
    }

    Scaffold(
        topBar = {
            Box {
                TopAppBar(title = { }, navigationIcon = { IconButton(onClick = back) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") } })
                TopProgressBar(work.busy, Modifier.align(Alignment.BottomCenter))
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
            GroupAvatar(c.id, 96.dp)
            Spacer(Modifier.height(16.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(c.name, style = MaterialTheme.typography.headlineSmall)
                if (canEdit) {
                    IconButton(onClick = { rename = true }) { Icon(Icons.Rounded.Edit, "Rename") }
                }
            }
            val active = r?.members?.count { it.role != Role.INVITED } ?: 0
            val invited = (r?.members?.size ?: 0) - active
            Text(
                when (m.state) {
                    GroupModel.INVITED -> "You're invited"
                    GroupModel.REMOVED -> "You were removed"
                    GroupModel.LEFT -> "You left this group"
                    else -> "Group · $active ${if (active == 1) "member" else "members"}" + if (invited > 0) ", $invited invited" else ""
                },
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            ProgressRow(work.busy, doing)
            Spacer(Modifier.height(16.dp))
            Surface(
                color = MaterialTheme.colorScheme.surfaceContainer,
                shape = MaterialTheme.shapes.large,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            ) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Rounded.Lock, null, tint = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.width(12.dp))
                    Text(
                        "Every message is end-to-end encrypted to each member separately. The server can't tell this is a group or who's in it.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            Spacer(Modifier.height(8.dp))

            Column(Modifier.fillMaxWidth()) {
                Text(
                    "${g.members.size} in the group",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(start = 24.dp, top = 12.dp, bottom = 4.dp),
                )
                if (amAdmin && (r?.members?.size ?: 0) < RosterRules.MAX_MEMBERS) {
                    SettingRow("Add members", null, Icons.Rounded.PersonAdd, onClick = { adding = true })
                }
                for (row in g.members) {
                    ListItem(
                        headlineContent = { Text(row.name, color = if (row.isMe) MaterialTheme.colorScheme.onSurface else memberColor(row.id)) },
                        supportingContent = {
                            val parts = buildList {
                                when (row.role) {
                                    Role.ADMIN -> add("Admin")
                                    Role.INVITED -> add("Invited")
                                }
                                if (!row.isMe && !row.isContact) {
                                    add("Not in your contacts · unverified")
                                } else if (!row.isMe && row.verified) {
                                    add("Verified")
                                }
                                if (row.serverIssue) {
                                    add("Can't reach or verify their server; messages to them wait")
                                }
                            }
                            if (parts.isNotEmpty()) {
                                Text(parts.joinToString(" · "))
                            }
                        },
                        leadingContent = { Avatar(row.name, row.id.hashCode().toLong(), 40.dp) },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier.clickable(enabled = !row.isMe) { selected = row }.padding(horizontal = 8.dp),
                    )
                }
                HorizontalDivider(Modifier.padding(vertical = 8.dp))
                SettingRow(
                    "Disappearing messages",
                    timerLabel(c.timerSecs) + if (!canEdit && joined) " · set by admins" else "",
                    Icons.Rounded.Timer,
                    enabled = canEdit,
                    onClick = { timer = true },
                )
                if (amAdmin) {
                    SwitchRow(
                        "Only admins can edit group info",
                        "The name and disappearing-messages timer",
                        Icons.Rounded.AdminPanelSettings,
                        checked = r?.adminsOnly == true,
                        onChange = { v -> act("Saving…") { Groups.setAdminsOnly(s, cid, v) } },
                    )
                }
                val hiddenOn by rememberQuery(s) { q -> !q.decoy && q.repo.kvString(app.goldfishsend.security.AppLock.KV_HIDDEN_ON) == "1" }
                if (hiddenOn == true) {
                    SwitchRow(
                        "Hide this chat",
                        "Keeps it out of the chat list until you enter your hidden-chats PIN",
                        Icons.Rounded.VisibilityOff,
                        checked = c.hidden,
                        onChange = { v -> scope.launch(Dispatchers.IO) { s.repo.setHidden(cid, v); s.db.notifyChanged() } },
                    )
                }
                SettingRow("Clear chat", "Delete all messages in this chat from this phone", Icons.Rounded.DeleteSweep, onClick = { confirmClear = true })
                if (joined) {
                    SettingRow("Leave group", "You'll stop getting messages from this group", Icons.AutoMirrored.Rounded.Logout, onClick = {
                        if (Groups.mustPromoteFirst(m, g.me)) promoteFirst = true else confirmLeave = true
                    })
                } else {
                    SettingRow("Delete group", "Erase this group and its messages from this phone", Icons.Rounded.DeleteForever, onClick = {
                        confirmDelete = true
                    })
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }

    selected?.let { row ->
        ModalBottomSheet(onDismissRequest = { selected = null }) {
            Column(Modifier.padding(bottom = 24.dp)) {
                Text(row.name, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp))
                val colors = ListItemDefaults.colors(containerColor = Color.Transparent)
                ListItem(
                    headlineContent = { Text("Safety number") },
                    supportingContent = { Text("Compare it with ${row.name} to make sure it's really them") },
                    leadingContent = { Icon(Icons.Rounded.Shield, null) },
                    colors = colors,
                    modifier = Modifier.clickable { safetyFor = row; selected = null },
                )
                if (amAdmin && row.role != Role.INVITED) {
                    val isAdmin = row.role == Role.ADMIN
                    ListItem(
                        headlineContent = { Text(if (isAdmin) "Remove as admin" else "Make admin") },
                        leadingContent = { Icon(Icons.Rounded.AdminPanelSettings, null) },
                        colors = colors,
                        modifier = Modifier.clickable {
                            selected = null
                            act("Updating ${row.name}…") { Groups.setAdmin(s, cid, row.id, !isAdmin) }
                        },
                    )
                }
                if (amAdmin) {
                    ListItem(
                        headlineContent = { Text(if (row.role == Role.INVITED) "Cancel invitation" else "Remove from group", color = MaterialTheme.colorScheme.error) },
                        leadingContent = { Icon(Icons.Rounded.PersonRemove, null, tint = MaterialTheme.colorScheme.error) },
                        colors = colors,
                        modifier = Modifier.clickable {
                            selected = null
                            confirmRemove = row
                        },
                    )
                }
            }
        }
    }
    confirmRemove?.let { row ->
        val invite = row.role == Role.INVITED
        AlertDialog(
            onDismissRequest = { confirmRemove = null },
            title = { Text(if (invite) "Cancel ${row.name}'s invitation?" else "Remove ${row.name}?") },
            text = {
                Text(
                    if (invite) {
                        "They won't be able to join with this invitation."
                    } else {
                        "${row.name} will stop getting messages from this group. Everyone moves to a new group inbox, which takes a moment."
                    },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmRemove = null
                    act(if (invite) "Cancelling the invitation…" else "Removing ${row.name}…") { Groups.removeMember(s, cid, row.id) }
                }) { Text(if (invite) "Cancel invitation" else "Remove", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = null }) { Text("Keep") } },
        )
    }
    safetyFor?.let { row ->
        val number by rememberQuery(s, row.id) { q -> safetyNumber(q, B64.dec(row.id)) }
        AlertDialog(
            onDismissRequest = { safetyFor = null },
            title = { Text("Safety number") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        if (row.isContact) {
                            "Compare this with the number on ${row.name}'s phone."
                        } else {
                            "${row.name} isn't in your contacts, so this number came from the group's admins. Compare it with them in person or on a call."
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.height(4.dp))
                    if (number == null) {
                        ProgressRow(true, "Calculating…")
                    }
                    for (line in number?.chunked(5)?.chunked(4).orEmpty()) {
                        Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                            for (gp in line) {
                                Text(gp, fontFamily = FontFamily.Monospace, fontSize = 17.sp, letterSpacing = 1.sp)
                            }
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { safetyFor = null }) { Text("Done") } },
        )
    }
    if (adding) {
        AddMembersDialog(s, r?.ids().orEmpty().toSet(), onDismiss = { adding = false }) { ids ->
            adding = false
            act(if (ids.size == 1) "Adding a member…" else "Adding ${ids.size} members…") { Groups.addMembers(s, cid, ids) }
        }
    }
    if (rename) {
        var name by remember { mutableStateOf(c.name) }
        AlertDialog(
            onDismissRequest = { rename = false },
            title = { Text("Group name") },
            text = { SecureTextField(name, { name = it.take(64) }, Modifier.fillMaxWidth(), hint = "Name", kind = FieldKind.TEXT) },
            confirmButton = {
                TextButton(enabled = name.isNotBlank(), onClick = {
                    rename = false
                    act("Renaming…") { Groups.rename(s, cid, name) }
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { rename = false }) { Text("Cancel") } },
        )
    }
    if (timer) {
        ChoiceDialog("Disappearing messages", TIMER_CHOICES.map { it to timerLabel(it) }, c.timerSecs, { timer = false }) { secs ->
            act("Saving…") { Groups.setTimer(s, cid, secs) }
        }
    }
    if (confirmClear) {
        ConfirmDialog("Clear chat?", "All messages in this group will be permanently erased from this phone.", "Clear", true, { confirmClear = false }) {
            erasing.run {
                withContext(Dispatchers.IO) {
                    s.repo.clearConversation(cid)
                    s.db.notifyChanged()
                    Notifier.cancel(Graph.app)
                }
            }
        }
    }
    if (promoteFirst) {
        AlertDialog(
            onDismissRequest = { promoteFirst = false },
            title = { Text("Choose a new admin first") },
            text = { Text("You're the only admin. Make someone else an admin (tap them in the member list), then leave.") },
            confirmButton = { TextButton(onClick = { promoteFirst = false }) { Text("OK") } },
        )
    }
    if (confirmLeave) {
        ConfirmDialog(
            "Leave ${c.name}?", "You'll stop getting messages from this group. The chat stays on this phone until you delete it.",
            "Leave", true, { confirmLeave = false },
        ) { act("Leaving the group…") { Groups.leave(s, cid) } }
    }
    if (confirmDelete) {
        ConfirmDialog("Delete ${c.name}?", "The group and all its messages will be erased from this phone.", "Delete", true, { confirmDelete = false }) {
            deleting.run {
                withContext(Dispatchers.IO) { Messenger.deleteContact(s, cid) }
                onDeleted()
            }
        }
    }
    BusyDialog(erasing.busy, "Clearing the chat…")
    BusyDialog(deleting.busy, "Deleting the group…", hint = "Telling the server to delete its inbox.")
}

@Composable
private fun AddMembersDialog(s: Session, already: Set<String>, onDismiss: () -> Unit, onAdd: (List<Long>) -> Unit) {
    val contacts by rememberQuery(s) { q -> invitable(q).filter { B64.enc(it.identityKey!!) !in already } }
    val picked = remember { mutableStateListOf<Long>() }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add members") },
        text = {
            val list = contacts.orEmpty()
            if (contacts != null && list.isEmpty()) {
                Text("Everyone in your contacts is already here.", textAlign = TextAlign.Start)
            }
            LazyColumn(Modifier.heightIn(max = 360.dp)) {
                items(list, key = { it.id }) { c ->
                    val on = c.id in picked
                    Row(
                        Modifier.fillMaxWidth().clickable { if (on) picked.remove(c.id) else picked.add(c.id) }.padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(on, onCheckedChange = null)
                        Spacer(Modifier.width(8.dp))
                        Text(c.name)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = picked.isNotEmpty(), onClick = { onAdd(picked.toList()) }, modifier = Modifier.blockWhenObscured()) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Shown instead of the composer while we're invited to a group: who invited us, Join or Decline. */
@Composable
fun GroupInvitationBar(s: Session, cid: Long, inviter: String, onError: (String) -> Unit, onDeclined: () -> Unit) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var joining by remember { mutableStateOf(false) }
    Surface(color = MaterialTheme.colorScheme.surfaceContainerHigh, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.navigationBarsPadding().padding(16.dp)) {
            Text("$inviter invited you to this group", style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text(
                "If you join, the members see your name and can message the group, including you. Members who aren't your contacts " +
                    "are unverified until you compare safety numbers.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ProgressButton(busy = busy && !joining, enabled = !busy, kind = ButtonKind.OUTLINED, onClick = {
                    busy = true
                    joining = false
                    scope.launch {
                        withContext(Dispatchers.IO) { runCatching { Groups.leave(s, cid) } }
                        busy = false
                        onDeclined()
                    }
                }, modifier = Modifier.weight(1f)) { Text("Decline") }
                ProgressButton(busy = busy && joining, enabled = !busy, onClick = {
                    busy = true
                    joining = true
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { runCatching { Groups.join(s, cid) } }
                        busy = false
                        r.onFailure { onError(groupError(it, "Couldn't join. Try again.")) }
                    }
                }, modifier = Modifier.weight(1f).blockWhenObscured()) {
                    Text("Join")
                }
            }
        }
    }
}

/** The message to show for a failed group action. Unexpected errors are logged by class (with the stack in debug builds). */
private fun groupError(e: Throwable, fallback: String): String {
    if (e is GroupException) {
        return e.human
    }
    android.util.Log.w("GoldfishSend", "group action failed: ${e.javaClass.simpleName}", e.takeIf { app.goldfishsend.BuildConfig.DEBUG })
    return fallback
}
