package com.example.webmil.browser.storage

import android.content.Context
import android.content.SharedPreferences
import com.example.webmil.browser.model.Bookmark
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Handles persistent storage and management of DoD / military / government web portal bookmarks.
 * Uses SharedPreferences with JSON encoding to ensure bookmarks persist across application restarts.
 */
class BookmarkStorage(private val context: Context? = null) {

    private val prefs: SharedPreferences? = context?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREFS_NAME = "webmil_portal_bookmarks"
        private const val KEY_BOOKMARKS = "saved_bookmarks_json"

        /**
         * Pre-loaded default DoD, Military, and Government web portals.
         */
        val defaultMilitaryPortals = listOf(
            Bookmark(
                id = "def-webmail-apps",
                title = "DoD Enterprise Webmail (O365)",
                url = "https://webmail.apps.mil",
                category = "Webmail",
                isDefault = true
            ),
            Bookmark(
                id = "def-badssl",
                title = "BadSSL mTLS Test",
                url = "https://client.badssl.com/",
                category = "Testing",
                isDefault = true
            ),
            Bookmark(
                id = "def-dod-main",
                title = "DoD Official Portal",
                url = "https://www.defense.gov/",
                category = "DoD Portal",
                isDefault = true
            ),
            Bookmark(
                id = "def-dts",
                title = "Defense Travel System (DTS)",
                url = "https://www.defensetravel.dod.mil/",
                category = "Travel & Admin",
                isDefault = true
            ),
            Bookmark(
                id = "def-owa",
                title = "DoD Enterprise OWA Webmail",
                url = "https://webmail.east.mail.mil/",
                category = "Webmail",
                isDefault = true
            ),
            Bookmark(
                id = "def-mypay",
                title = "DFAS myPay Portal",
                url = "https://mypay.dfas.mil/",
                category = "Finance & Pay",
                isDefault = true
            ),
            Bookmark(
                id = "def-cyberexchange",
                title = "DoD Cyber Exchange",
                url = "https://cyber.mil/",
                category = "Cybersecurity",
                isDefault = true
            ),
            Bookmark(
                id = "def-piv-gsa",
                title = "GSA PIV Identity Management",
                url = "https://piv.idmanagement.gov/",
                category = "PKI & Identity",
                isDefault = true
            ),
            Bookmark(
                id = "def-navy-pki",
                title = "U.S. Navy PKI Portal",
                url = "https://www.navy.mil/",
                category = "Service Portal",
                isDefault = true
            ),
            Bookmark(
                id = "def-army-portal",
                title = "U.S. Army Enterprise Portal",
                url = "https://www.army.mil/",
                category = "Service Portal",
                isDefault = true
            ),
            Bookmark(
                id = "def-af-portal",
                title = "U.S. Air Force Portal",
                url = "https://www.af.mil/",
                category = "Service Portal",
                isDefault = true
            )
        )
    }

    /**
     * Loads saved bookmarks from SharedPreferences, merging with default military portals if needed.
     */
    fun loadBookmarks(): List<Bookmark> {
        if (prefs == null) return defaultMilitaryPortals

        val jsonString = prefs.getString(KEY_BOOKMARKS, null)
        if (jsonString.isNullOrEmpty()) {
            saveBookmarks(defaultMilitaryPortals)
            return defaultMilitaryPortals
        }

        return try {
            val jsonArray = JSONArray(jsonString)
            val list = mutableListOf<Bookmark>()
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                list.add(
                    Bookmark(
                        id = obj.optString("id", UUID.randomUUID().toString()),
                        title = obj.getString("title"),
                        url = obj.getString("url"),
                        category = obj.optString("category", "Government"),
                        isDefault = obj.optBoolean("isDefault", false)
                    )
                )
            }
            if (list.isEmpty()) defaultMilitaryPortals else list
        } catch (e: Exception) {
            defaultMilitaryPortals
        }
    }

    /**
     * Saves the list of bookmarks to SharedPreferences as a JSON array.
     */
    fun saveBookmarks(bookmarks: List<Bookmark>) {
        val prefsEditor = prefs?.edit() ?: return
        val jsonArray = JSONArray()
        for (bookmark in bookmarks) {
            val obj = JSONObject().apply {
                put("id", bookmark.id)
                put("title", bookmark.title)
                put("url", bookmark.url)
                put("category", bookmark.category)
                put("isDefault", bookmark.isDefault)
            }
            jsonArray.put(obj)
        }
        prefsEditor.putString(KEY_BOOKMARKS, jsonArray.toString())
        prefsEditor.apply()
    }

    /**
     * Adds a bookmark to storage if not already present.
     */
    fun addBookmark(currentList: List<Bookmark>, title: String, url: String, category: String = "Government"): List<Bookmark> {
        val formattedUrl = if (url.startsWith("http://", ignoreCase = true) || url.startsWith("https://", ignoreCase = true)) url else "https://$url"
        if (currentList.any { it.url.equals(formattedUrl, ignoreCase = true) }) {
            return currentList
        }
        val newBookmark = Bookmark(
            id = UUID.randomUUID().toString(),
            title = title.ifBlank { formattedUrl },
            url = formattedUrl,
            category = category,
            isDefault = false
        )
        val updated = currentList + newBookmark
        saveBookmarks(updated)
        return updated
    }

    /**
     * Deletes a bookmark by URL or ID.
     */
    fun deleteBookmark(currentList: List<Bookmark>, url: String): List<Bookmark> {
        val updated = currentList.filterNot { it.url.equals(url, ignoreCase = true) || it.id == url }
        saveBookmarks(updated)
        return updated
    }

    /**
     * Toggles bookmark state for a given URL.
     */
    fun toggleBookmark(currentList: List<Bookmark>, url: String, title: String): List<Bookmark> {
        val formattedUrl = if (url.startsWith("http://", ignoreCase = true) || url.startsWith("https://", ignoreCase = true)) url else "https://$url"
        val existing = currentList.find { it.url.equals(formattedUrl, ignoreCase = true) }
        val updated = if (existing != null) {
            currentList.filterNot { it.url.equals(formattedUrl, ignoreCase = true) }
        } else {
            currentList + Bookmark(
                id = UUID.randomUUID().toString(),
                title = title.ifBlank { formattedUrl },
                url = formattedUrl,
                category = "Custom",
                isDefault = false
            )
        }
        saveBookmarks(updated)
        return updated
    }
}
