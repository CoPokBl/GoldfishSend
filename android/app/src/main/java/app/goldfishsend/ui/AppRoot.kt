package app.goldfishsend.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.material3.SnackbarHost
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
            Graph.vault.hasPassphrase -> RootState.LOCKED
            else -> RootState.UNLOCKING
        }
    }
    AnimatedContent(state, transitionSpec = { fadeIn() togetherWith fadeOut() }, label = "root") { st ->
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
    LaunchedEffect(link) {
        val raw = link ?: return@LaunchedEffect
        pendingLink.value = null
        acceptInvite(s, raw, viaQr = false)
            .onSuccess { id -> nav.navigate("chat/$id") { popUpTo("home") } }
            .onFailure { snackbar.showSnackbar(it.message ?: "Couldn't add that contact.") }
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
                )
            }
            composable("chat/{id}", arguments = listOf(navArgument("id") { type = NavType.LongType })) { e ->
                val id = e.arguments!!.getLong("id")
                ChatScreen(s, id, back = { nav.popBackStack() }, openInfo = { nav.navigate("contact/$id") })
            }
            composable("contact/{id}", arguments = listOf(navArgument("id") { type = NavType.LongType })) { e ->
                val id = e.arguments!!.getLong("id")
                ContactInfoScreen(s, id, back = { nav.popBackStack() }, onDeleted = { nav.popBackStack("home", inclusive = false) })
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
