package com.example.webmil.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.ArrowForward
import androidx.compose.material.icons.rounded.Bookmark
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.LockOpen
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Star
import androidx.compose.material.icons.rounded.StarOutline
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.webmil.browser.model.Bookmark
import com.example.webmil.browser.model.WebTab

@Composable
fun WebAddressBar(
    activeTab: WebTab?,
    bookmarks: List<Bookmark>,
    onNavigate: (String) -> Unit,
    onBackClick: () -> Unit,
    onForwardClick: () -> Unit,
    onRefreshClick: () -> Unit,
    onStopClick: () -> Unit,
    onBookmarkToggle: (String, String) -> Unit,
    onSecurityClick: () -> Unit,
    onBookmarkManageClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    var urlText by remember { mutableStateOf(activeTab?.url ?: "") }

    LaunchedEffect(activeTab?.url) {
        if (activeTab != null && activeTab.url != urlText) {
            urlText = activeTab.url
        }
    }

    val isSecure = activeTab?.securityInfo?.isSecure ?: false
    val isMtls = activeTab?.securityInfo?.isMtlsAuthenticated ?: false

    val lockColor = when {
        isMtls -> Color(0xFF2E7D32) // Bright Green for mTLS
        isSecure -> Color(0xFF1565C0) // Blue for standard HTTPS
        else -> Color(0xFFE65100) // Orange for HTTP / Warning
    }

    Surface(
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 2.dp,
        modifier = modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Back Button
                IconButton(
                    onClick = onBackClick,
                    enabled = activeTab?.canGoBack == true,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                        contentDescription = "Back",
                        tint = if (activeTab?.canGoBack == true)
                            MaterialTheme.colorScheme.onSurface
                        else
                            MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
                    )
                }

                // Forward Button
                IconButton(
                    onClick = onForwardClick,
                    enabled = activeTab?.canGoForward == true,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Rounded.ArrowForward,
                        contentDescription = "Forward",
                        tint = if (activeTab?.canGoForward == true)
                            MaterialTheme.colorScheme.onSurface
                        else
                            MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
                    )
                }

                // Refresh / Stop Button
                IconButton(
                    onClick = {
                        if (activeTab?.isLoading == true) onStopClick() else onRefreshClick()
                    },
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = if (activeTab?.isLoading == true)
                            Icons.Rounded.Close
                        else
                            Icons.Rounded.Refresh,
                        contentDescription = if (activeTab?.isLoading == true) "Stop" else "Refresh"
                    )
                }

                Spacer(modifier = Modifier.width(4.dp))

                // URL Input Field with SSL Lock Icon & Bookmark Star
                OutlinedTextField(
                    value = urlText,
                    onValueChange = { urlText = it },
                    singleLine = true,
                    placeholder = { Text("Search or enter web URL (https://...)") },
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Go),
                    keyboardActions = KeyboardActions(onGo = { onNavigate(urlText) }),
                    leadingIcon = {
                        IconButton(
                            onClick = onSecurityClick,
                            modifier = Modifier.size(28.dp)
                        ) {
                            Icon(
                                imageVector = if (isSecure || isMtls) Icons.Rounded.Lock else Icons.Rounded.LockOpen,
                                contentDescription = "Security Status",
                                tint = lockColor,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    },
                    trailingIcon = {
                        IconButton(
                            onClick = {
                                activeTab?.let { tab ->
                                    onBookmarkToggle(tab.url, tab.title)
                                }
                            },
                            modifier = Modifier.size(28.dp)
                        ) {
                            Icon(
                                imageVector = if (activeTab?.isBookmarked == true)
                                    Icons.Rounded.Star
                                else
                                    Icons.Rounded.StarOutline,
                                contentDescription = "Bookmark",
                                tint = if (activeTab?.isBookmarked == true) Color(0xFFFFB300) else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                        focusedBorderColor = lockColor,
                        unfocusedBorderColor = Color.Transparent
                    ),
                    shape = RoundedCornerShape(24.dp),
                    modifier = Modifier
                        .weight(1f)
                        .padding(vertical = 2.dp)
                )
            }

            // Quick Bookmark Chips Row
            LazyRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (onBookmarkManageClick != null) {
                    item {
                        AssistChip(
                            onClick = onBookmarkManageClick,
                            label = { Text("Manage Portals", fontSize = 11.sp, fontWeight = FontWeight.Bold) },
                            leadingIcon = {
                                Icon(
                                    imageVector = Icons.Rounded.Bookmark,
                                    contentDescription = null,
                                    modifier = Modifier.size(14.dp)
                                )
                            },
                            colors = AssistChipDefaults.assistChipColors(
                                containerColor = MaterialTheme.colorScheme.primaryContainer
                            ),
                            shape = RoundedCornerShape(12.dp)
                        )
                    }
                }

                items(bookmarks) { bookmark ->
                    AssistChip(
                        onClick = {
                            urlText = bookmark.url
                            onNavigate(bookmark.url)
                        },
                        label = {
                            Text(
                                text = bookmark.title,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium
                            )
                        },
                        colors = AssistChipDefaults.assistChipColors(
                            containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.6f)
                        ),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.padding(0.dp)
                    )
                }
            }
        }
    }
}
