package com.example.webmil

import com.example.webmil.browser.WebBrowserManager
import com.example.webmil.browser.storage.BookmarkStorage
import com.example.webmil.ui.components.extractEdipiAndCn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WebBrowserTest {

    @Test
    fun testTabManagementAddAndSelect() {
        val manager = WebBrowserManager()
        var state = manager.uiState.value

        // Initial state has 1 default tab
        assertEquals(1, state.tabs.size)
        val firstTabId = state.activeTabId
        assertNotNull(state.activeTab)

        // Add a second tab
        val secondTabId = manager.addTab("https://www.defense.gov/", title = "DoD Portal")
        state = manager.uiState.value

        assertEquals(2, state.tabs.size)
        assertEquals(secondTabId, state.activeTabId)
        assertEquals("https://www.defense.gov/", state.activeTab?.url)

        // Switch back to first tab
        manager.selectTab(firstTabId)
        state = manager.uiState.value
        assertEquals(firstTabId, state.activeTabId)
    }

    @Test
    fun testTabCloseAndFallback() {
        val manager = WebBrowserManager()
        val firstTabId = manager.uiState.value.activeTabId

        // Close the only tab -> Should auto-recreate a default new tab
        manager.closeTab(firstTabId)
        val state = manager.uiState.value

        assertEquals(1, state.tabs.size)
        assertTrue(state.activeTabId.isNotEmpty())
        assertNotNull(state.activeTab)
    }

    @Test
    fun testUrlFormattingAndHostParsing() {
        assertEquals("https://webmail.apps.mil", WebBrowserManager.formatUrl("webmail.apps.mil"))
        assertEquals("https://example.com", WebBrowserManager.formatUrl("https://example.com"))
        assertEquals("http://test.com", WebBrowserManager.formatUrl("http://test.com"))

        assertEquals("webmail.apps.mil", WebBrowserManager.parseHost("https://webmail.apps.mil/owa"))
    }

    @Test
    fun testBookmarkToggle() {
        val manager = WebBrowserManager()
        val testUrl = "https://custom.mil/"
        manager.addTab(testUrl, title = "Custom MIL")

        assertFalse(manager.isUrlBookmarked(testUrl))

        manager.toggleBookmark(testUrl, "Custom MIL")
        assertTrue(manager.isUrlBookmarked(testUrl))
        assertTrue(manager.uiState.value.activeTab?.isBookmarked == true)

        manager.toggleBookmark(testUrl, "Custom MIL")
        assertFalse(manager.isUrlBookmarked(testUrl))
    }

    @Test
    fun testPreloadedMilitaryBookmarks() {
        val manager = WebBrowserManager()
        val bookmarks = manager.listBookmarks()

        assertTrue("Should preload default military portals", bookmarks.isNotEmpty())
        assertTrue("Contains DoD Webmail portal", bookmarks.any { it.url.contains("webmail.apps.mil") })
        assertTrue("Contains BadSSL test portal", bookmarks.any { it.url.contains("badssl") })
        assertTrue("Contains DoD portal", bookmarks.any { it.title.contains("DoD") })
        assertTrue("Contains DTS portal", bookmarks.any { it.title.contains("Travel") })
        assertTrue("Contains OWA Webmail", bookmarks.any { it.title.contains("OWA") })
        assertTrue("Contains myPay", bookmarks.any { it.title.contains("myPay") })
        assertTrue("Contains Cyber Exchange", bookmarks.any { it.title.contains("Cyber") })
    }

    @Test
    fun testBookmarkAddDeleteListManagement() {
        val manager = WebBrowserManager()
        val customTitle = "Army Reserve Portal"
        val customUrl = "https://www.usar.army.mil/"

        // 1. Add Bookmark
        manager.addBookmark(customUrl, customTitle, category = "Service Portal")
        assertTrue(manager.isUrlBookmarked(customUrl))

        val listAfterAdd = manager.listBookmarks()
        val added = listAfterAdd.find { it.url == customUrl }
        assertNotNull(added)
        assertEquals(customTitle, added?.title)
        assertEquals("Service Portal", added?.category)

        // 2. Delete Bookmark
        manager.deleteBookmark(customUrl)
        assertFalse(manager.isUrlBookmarked(customUrl))
        assertNull(manager.listBookmarks().find { it.url == customUrl })
    }

    @Test
    fun testBookmarkStorageMemoryManagement() {
        val storage = BookmarkStorage(context = null)
        val initial = storage.loadBookmarks()
        assertTrue(initial.size >= 5)

        val updated = storage.addBookmark(initial, title = "DLA Portal", url = "https://www.dla.mil/", category = "Logistics")
        assertTrue(updated.any { it.title == "DLA Portal" })

        val afterDelete = storage.deleteBookmark(updated, url = "https://www.dla.mil/")
        assertFalse(afterDelete.any { it.title == "DLA Portal" })
    }

    @Test
    fun testDodEdipiAndCommonNameExtraction() {
        val dodSubject = "CN=DOE.JOHN.A.1234567890, OU=USA, OU=PKI, OU=DoD, O=U.S. Government, C=US"
        val (cn, edipi) = extractEdipiAndCn(dodSubject)

        assertEquals("DOE.JOHN.A.1234567890", cn)
        assertEquals("1234567890", edipi)

        val simSubject = "CN=CAC Cardholder (Simulated DoD PIV), OU=DoD PKI, O=U.S. Government, C=US"
        val (simCn, simEdipi) = extractEdipiAndCn(simSubject)

        assertEquals("CAC Cardholder (Simulated DoD PIV)", simCn)
        assertNull(simEdipi)
    }
}
