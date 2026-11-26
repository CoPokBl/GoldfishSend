package app.goldfishsend.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.material3.SnackbarHost
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.material3.SnackbarHostState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import app.goldfishsend.core.Actions
import app.goldfishsend.core.Graph
import app.goldfishsend.core.Session
import app.goldfishsend.ui.screens.AddContactScreen
import app.goldfishsend.ui.screens.ChatScreen
import app.goldfishsend.ui.screens.ContactInfoScreen
import app.goldfishsend.ui.screens.HomeScreen
import app.goldfishsend.ui.screens.LockScreen
import app.goldfishsend.ui.screens.OnboardingFlow
import app.goldfishsend.ui.screens.PassphraseScreen
import app.goldfishsend.ui.screens.UnlockingSplash
import app.goldfishsend.ui.screens.acceptInvite
import kotlinx.coroutines.flow.MutableStateFlow
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import app.goldfishsend.proto.InviteLink
import app.goldfishsend.ui.components.blockWhenObscured

private enum class RootState { ONBOARDING, LOCKED, UNLOCKING, READY }

/** Top-level state machine: onboarding → locked/unlocking → app. */
@Composable
fun AppRoot(pendingLink: MutableStateFlow<String?>) {
    val prefsVersion by Graph.prefs.version.collectAsState()
    val session by Graph.session.collectAsState()
    val state = prefsVersion.let {
        when {
            !Graph.prefs.onboarded -> RootState.ONBOARDING
            session != null -> RootState.READY
            Graph.vault.requiresUserUnlock -> RootState.LOCKED
            else -> RootState.UNLOCKING
        }
    }
    AnimatedContent(
        state,
        transitionSpec = {
            if (FirstFrame.drawn) fadeIn() togetherWith fadeOut() else EnterTransition.None togetherWith ExitTransition.None
        },
        label = "root",
    ) { st ->
        when (st) {
            RootState.ONBOARDING -> OnboardingFlow()
            RootState.LOCKED -> LockScreen()
            RootState.UNLOCKING -> UnlockingSplash()
            RootState.READY -> session?.let { MainNav(it, pendingLink) }
        }
    }
    // A pinned server presented a different key: ask the user, whatever screen is showing.
    app.goldfishsend.ui.screens.PinMismatchDialog()
}

@Composable
private fun MainNav(s: Session, pendingLink: MutableStateFlow<String?>) {
    val nav = rememberNavController()
    val snackbar = remember { SnackbarHostState() }
    val link by pendingLink.collectAsState()
    var confirmLink by remember { mutableStateOf<String?>(null) }
    var accepting by remember { mutableStateOf<String?>(null) }
    // An opened link only proposes a contact. Nothing is fetched or sent until the user accepts.
    LaunchedEffect(link) {
        val raw = link ?: return@LaunchedEffect
        pendingLink.value = null
        confirmLink = raw
    }
    var adding by remember { mutableStateOf(false) }
    LaunchedEffect(accepting) {
        val raw = accepting ?: return@LaunchedEffect
        accepting = null
        adding = true
        val r = acceptInvite(s, raw, viaQr = false)
        adding = false
        r.onSuccess { id -> nav.navigate("chat/$id") { popUpTo("home") } }
            .onFailure { snackbar.showSnackbar(it.message ?: "Couldn't add that contact.") }
    }
    app.goldfishsend.ui.components.BusyDialog(adding, "Adding contact…")
    // Group create and join run on after their screen is gone (Actions), so their failures are shown here, wherever the
    // user is. Collected only while the app is on screen, so one that fails in the background shows on return. Only this
    // session's own: nothing a locked session started may show in the next one.
    val failures by Actions.failures.collectAsStateWithLifecycle()
    val failure = failures.firstOrNull { it.owner === s.scope }
    LaunchedEffect(failure) {
        val f = failure ?: return@LaunchedEffect
        snackbar.showSnackbar(f.message, withDismissAction = true)
        Actions.consume(f)
    }
    // Our own server presented a different identity key: explain, and let the user trust it (after re-authenticating).
    app.goldfishsend.ui.screens.ServerIdentityChangedDialog(s)
    confirmLink?.takeIf { InviteLink.isOutdated(it) }?.let {
        AlertDialog(
            onDismissRequest = { confirmLink = null },
            title = { Text("This invite is out of date") },
            text = { Text("It was made by an older version of GoldfishSend. Ask them to update the app and send you a new one.") },
            confirmButton = { TextButton(onClick = { confirmLink = null }) { Text("OK") } },
        )
    }
    confirmLink?.takeUnless { InviteLink.isOutdated(it) }?.let { raw ->
        val host = InviteLink.parse(raw)?.server?.let { runCatching { java.net.URI(it).host }.getOrNull() } ?: "an unknown server"
        AlertDialog(
            onDismissRequest = { confirmLink = null },
            title = { Text("Add a contact from a link?") },
            text = {
                Text(
                    "Someone shared an invite on $host. If you accept, they'll be able to message you and will see your name. " +
                        "They'll be unverified until you compare safety numbers. Only accept links from people you know.",
                )
            },
            confirmButton = {
                TextButton(onClick = { accepting = raw; confirmLink = null }, modifier = Modifier.blockWhenObscured()) { Text("Accept") }
            },
            dismissButton = { TextButton(onClick = { confirmLink = null }) { Text("Decline") } },
        )
    }
    Box(Modifier.fillMaxSize()) {
        NavHost(
            nav,
            startDestination = "home",
            enterTransition = { slideInHorizontally { it / 4 } + fadeIn() },
            exitTransition = { fadeOut() },
            popEnterTransition = { fadeIn() },
            popExitTransition = { slideOutHorizontally { it / 4 } + fadeOut() },
        ) {
            composable("home") {
                HomeScreen(
                    s,
                    openChat = { nav.navigate("chat/$it") },
                    addContact = { nav.navigate("add") },
                    openPassphrase = { nav.navigate("passphrase") },
                    newGroup = { nav.navigate("newgroup") },
                )
            }
            composable("newgroup") {
                app.goldfishsend.ui.screens.NewGroupScreen(s, back = { nav.popBackStack() }, openChat = { id -> nav.navigate("chat/$id") { popUpTo("home") } })
            }
            composable("chat/{id}", arguments = listOf(navArgument("id") { type = NavType.LongType })) { e ->
                val id = e.arguments!!.getLong("id")
                ChatScreen(s, id, back = { nav.popBackStack() }, openInfo = { nav.navigate("contact/$id") })
            }
            composable("contact/{id}", arguments = listOf(navArgument("id") { type = NavType.LongType })) { e ->
                val id = e.arguments!!.getLong("id")
                val isGroup by app.goldfishsend.ui.components.rememberQuery(s, id) { it.repo.contact(id)?.isGroup }
                when (isGroup) {
                    true -> app.goldfishsend.ui.screens.GroupInfoScreen(s, id, back = { nav.popBackStack() }, onDeleted = { nav.popBackStack("home", inclusive = false) })
                    false -> ContactInfoScreen(s, id, back = { nav.popBackStack() }, onDeleted = { nav.popBackStack("home", inclusive = false) })
                    null -> Unit
                }
            }
            composable("add") {
                AddContactScreen(s, back = { nav.popBackStack() }, openChat = { id -> nav.navigate("chat/$id") { popUpTo("home") } })
            }
            composable("passphrase") {
                PassphraseScreen(s, back = { nav.popBackStack() })
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).navigationBarsPadding())
    }
}
