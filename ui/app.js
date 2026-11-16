/* MD-Vault Desktop Frontend Controller */
(function () {
  "use strict";

  const state = {
    vaultName: "我的账号密码库",
    vaultPath: "",
    categories: [],
    entries: [],
    tagCounts: {},
    savedTags: {},
    editingCustomFields: null,
    filterType: "all", // "all" | "favorite" | "health" | "category"
    filterCategory: "",
    filterTag: "",
    searchQuery: "",
    selectedId: null,
    mode: "view", // "view" | "edit"
    revealedSecrets: new Map(),
    totpTimer: null,
    totpState: null,
    healthReport: null,
    appVersion: "0.2.1",
    autoCheckUpdates: true,
    autoLockMinutes: 15,
    lockOnMinimize: false,
    lastActivityAt: Date.now(),
    lockingInProgress: false,
    updateInfo: null,
    startupUpdateChecked: false,
  };

  const $ = (id) => document.getElementById(id);

  function api() {
    if (window.pywebview && window.pywebview.api) {
      return window.pywebview.api;
    }
    throw new Error("桌面桥接接口尚未就绪");
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function showToast(message, type = "info") {
    const container = $("toast-container");
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => {
      el.style.opacity = "0";
      el.style.transition = "opacity 0.25s ease";
      setTimeout(() => el.remove(), 260);
    }, 2800);
  }

  function pickAvatarLabel(entry) {
    const combined = `${entry.platform || ""} ${entry.title || ""} ${entry.category || ""}`.toLowerCase();
    if (combined.includes("apple") || combined.includes("icloud") || combined.includes("苹果")) return "🍎";
    if (
      combined.includes("mail") ||
      combined.includes("outlook") ||
      combined.includes("邮箱") ||
      combined.includes("qq") ||
      combined.includes("163")
    ) {
      return "✉️";
    }
    if (combined.includes("github") || combined.includes("aws") || combined.includes("开发") || combined.includes("云")) {
      return "💻";
    }
    if (combined.includes("steam") || combined.includes("游戏") || combined.includes("epic")) {
      return "🎮";
    }
    const clean = (entry.platform || entry.title || "?").trim();
    return clean.charAt(0).toUpperCase();
  }

  // ==================== MODAL HELPER ====================
  function openModal({ title, bodyHtml, footerButtons = [], wide = false }) {
    const card = $("modal-card");
    if (card) card.classList.toggle("wide", Boolean(wide));
    $("modal-title").textContent = title;
    $("modal-body").innerHTML = bodyHtml;
    const footer = $("modal-footer");
    footer.innerHTML = "";
    footerButtons.forEach((btnCfg) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `btn ${btnCfg.className || "btn-ghost"}`;
      btn.textContent = btnCfg.label;
      btn.addEventListener("click", () => {
        if (btnCfg.onClick) btnCfg.onClick();
      });
      footer.appendChild(btn);
    });
    $("modal-overlay").classList.remove("hidden");
  }

  function closeModal() {
    $("modal-overlay").classList.add("hidden");
    const card = $("modal-card");
    if (card) card.classList.remove("wide");
    $("modal-body").innerHTML = "";
    $("modal-footer").innerHTML = "";
  }

  // ==================== SECURITY, AUTO-LOCK & CONFLICT HELPERS ====================
  function isWorkspaceUnlocked() {
    const ws = $("app-workspace");
    return Boolean(ws && !ws.classList.contains("hidden"));
  }

  function syncAutoLockLabel() {
    const labelEl = $("settings-autolock-label");
    if (!labelEl) return;
    if (!state.autoLockMinutes || state.autoLockMinutes <= 0) {
      labelEl.textContent = state.lockOnMinimize ? "仅最小化" : "关闭";
    } else if (state.autoLockMinutes >= 60 && state.autoLockMinutes % 60 === 0) {
      labelEl.textContent = `${state.autoLockMinutes / 60} 小时`;
    } else {
      labelEl.textContent = `${state.autoLockMinutes} 分钟`;
    }
  }

  function clearTotpIntervalOnly() {
    if (state.totpTimer) {
      clearInterval(state.totpTimer);
      state.totpTimer = null;
    }
  }

  function stopTotpTimer() {
    clearTotpIntervalOnly();
    state.totpState = null;
  }

  function formatTotpCode(code) {
    const s = String(code || "").trim();
    if (s.length === 6) return `${s.slice(0, 3)} ${s.slice(3)}`;
    if (s.length === 8) return `${s.slice(0, 4)} ${s.slice(4)}`;
    return s;
  }

  function syncTotpDomElements() {
    const t = state.totpState;
    if (!t || t.noTotp) return;
    const codeEl = $("totp-code-val");
    const countEl = $("totp-countdown-val");
    const fillEl = $("totp-progress-fill");
    if (!codeEl || !countEl || !fillEl) return;
    if (t.error) {
      codeEl.textContent = "配置无效";
      codeEl.classList.add("expiring");
      countEl.textContent = "请检查密钥";
      fillEl.style.width = "0%";
      return;
    }
    const rem = Math.max(0, Number(t.remaining) || 0);
    const period = Math.max(1, Number(t.period) || 30);
    const expiring = rem <= 5;
    codeEl.textContent = formatTotpCode(t.code);
    codeEl.classList.toggle("expiring", expiring);
    countEl.textContent = `${rem}s 后刷新`;
    countEl.classList.toggle("expiring", expiring);
    fillEl.style.width = `${Math.min(100, Math.max(0, (rem / period) * 100))}%`;
    fillEl.classList.toggle("expiring", expiring);
  }

  function ensureTotpInterval(entryId) {
    if (state.totpTimer) return;
    state.totpTimer = setInterval(() => {
      if (
        !isWorkspaceUnlocked() ||
        state.mode !== "view" ||
        state.filterType === "health" ||
        state.selectedId !== entryId
      ) {
        stopTotpTimer();
        return;
      }
      if (!state.totpState || state.totpState.error || state.totpState.noTotp) {
        clearTotpIntervalOnly();
        return;
      }
      state.totpState.remaining = (Number(state.totpState.remaining) || 1) - 1;
      if (state.totpState.remaining <= 0) {
        refreshTotpFromBackend(entryId);
      } else {
        syncTotpDomElements();
      }
    }, 1000);
  }

  async function refreshTotpFromBackend(entryId) {
    try {
      const res = await api().get_entry_totp(entryId);
      if (state.selectedId !== entryId || state.mode !== "view" || state.filterType === "health") {
        return;
      }
      if (res && res.ok) {
        const hadLiveDom = Boolean($("totp-code-val"));
        state.totpState = {
          entryId,
          code: res.code,
          remaining: res.remaining,
          period: res.period,
          digits: res.digits,
          source: res.source || "totp_secret",
          noTotp: false,
          error: null,
        };
        ensureTotpInterval(entryId);
        if (!hadLiveDom) {
          renderRightPane();
        } else {
          syncTotpDomElements();
        }
      } else if (res && res.no_totp) {
        clearTotpIntervalOnly();
        state.totpState = { entryId, noTotp: true, error: null };
      } else {
        clearTotpIntervalOnly();
        state.totpState = {
          entryId,
          noTotp: false,
          error: (res && res.error) || "无效密钥",
        };
        syncTotpDomElements();
      }
    } catch (_) {
      // Ignore transient errors while locked
    }
  }

  function startTotpLoop(entryId) {
    stopTotpTimer();
    refreshTotpFromBackend(entryId);
    ensureTotpInterval(entryId);
  }

  async function updateEditorTotpPreview() {
    const inputEl = $("field-2fa");
    const previewEl = $("totp-editor-preview");
    if (!inputEl || !previewEl) return;
    const val = inputEl.value.trim();
    if (!val) {
      previewEl.classList.add("hidden");
      previewEl.innerHTML = "";
      return;
    }
    try {
      const res = await api().preview_totp_secret(val);
      if ($("field-2fa").value.trim() !== val) return;
      previewEl.classList.remove("hidden");
      if (res && res.ok) {
        previewEl.innerHTML = `<span style="color:var(--success);font-weight:600">✓ 已识别 TOTP 动态码密钥 · 实时验证码：${escapeHtml(
          formatTotpCode(res.code)
        )}</span><span>每 ${Number(res.period) || 30}s 刷新（剩余 ${Number(res.remaining) || 0}s）</span>`;
      } else if (res && res.invalid_uri) {
        previewEl.innerHTML = `<span style="color:var(--danger);font-weight:600">✕ ${escapeHtml(
          res.error || "otpauth:// 链接格式无效"
        )}</span><span>请检查链接中的 secret 参数</span>`;
      } else {
        previewEl.innerHTML = `<span style="color:var(--text-muted)">ℹ 将作为加密备用恢复码保存（如需自动生成 6 位动态码，可填入 Base32 密钥或 otpauth:// 链接）</span>`;
      }
    } catch (_) {
      previewEl.classList.add("hidden");
    }
  }

  async function updateStrengthMeter(password, wrapId, fillId, hintId) {
    const wrap = $(wrapId);
    const fill = $(fillId);
    const hint = $(hintId);
    if (!wrap || !fill || !hint) return;
    if (!password) {
      wrap.classList.add("hidden");
      return;
    }
    wrap.classList.remove("hidden");
    try {
      const res = await api().check_password_strength(password, "");
      if (!res || !res.ok) return;
      const pctMap = { 0: 14, 1: 32, 2: 58, 3: 82, 4: 100 };
      const colorMap = {
        0: "var(--danger)",
        1: "var(--danger)",
        2: "var(--warning)",
        3: "var(--accent)",
        4: "var(--success)",
      };
      const sc = Number(res.score) || 0;
      fill.style.width = `${pctMap[sc] || 20}%`;
      fill.style.backgroundColor = colorMap[sc] || "var(--accent)";
      const warnText =
        res.warnings && res.warnings.length > 0
          ? res.warnings[0]
          : `约 ${res.entropy_bits} bits 熵值`;
      hint.innerHTML = `<span style="color:${colorMap[sc]};font-weight:600">强度：${escapeHtml(
        res.label
      )}</span><span>${escapeHtml(warnText)}</span>`;
    } catch (_) {
      wrap.classList.add("hidden");
    }
  }

  function clearSensitiveDomInputs() {
    [
      "field-password",
      "field-2fa",
      "unlock-password",
      "create-password",
      "create-password-confirm",
    ].forEach((id) => {
      const el = $(id);
      if (el) el.value = "";
    });
    const qaBox = $("qa-rows-container");
    if (qaBox) qaBox.innerHTML = "";
    const detailEl = $("detail-view");
    if (detailEl) detailEl.innerHTML = "";
    const healthEl = $("health-view");
    if (healthEl) healthEl.innerHTML = "";
  }

  async function lockWorkspaceWithReason(reason = "密码库已安全锁定") {
    if (state.lockingInProgress) return;
    state.lockingInProgress = true;
    try {
      stopTotpTimer();
      closeModal();
      closeSettingsPopover();
      clearSensitiveDomInputs();
      const status = await api().lock_vault();
      state.entries = [];
      state.revealedSecrets.clear();
      state.healthReport = null;
      state.mode = "view";
      renderAuthStatus(status);
      if (reason) showToast(reason, "info");
    } finally {
      state.lockingInProgress = false;
    }
  }

  function touchActivity() {
    if (isWorkspaceUnlocked() && !state.lockingInProgress) {
      const mins = Number(state.autoLockMinutes) || 0;
      if (mins > 0 && Date.now() - state.lastActivityAt >= mins * 60 * 1000) {
        checkIdleAutoLock();
        return;
      }
    }
    const now = Date.now();
    if (now - state.lastActivityAt > 1000) {
      state.lastActivityAt = now;
    }
  }

  function checkIdleAutoLock() {
    if (!isWorkspaceUnlocked() || state.lockingInProgress) return;
    const mins = Number(state.autoLockMinutes) || 0;
    if (mins <= 0) return;
    const elapsedMs = Date.now() - state.lastActivityAt;
    if (elapsedMs >= mins * 60 * 1000) {
      lockWorkspaceWithReason(`已超过 ${mins} 分钟未操作，密码库已自动安全锁定`);
    }
  }

  function openConflictModal(retryWithMode) {
    const syncBtn = $("btn-sync-external");
    if (syncBtn) syncBtn.classList.remove("hidden");

    openModal({
      title: "⚠️ 检测到外部文件修改冲突",
      wide: true,
      bodyHtml: `
        <p style="font-size:13px;line-height:1.65;color:var(--text-primary);margin-bottom:10px">
          本地 <code>.md</code> 密码库文件在您编辑期间已被外部程序（如 Obsidian、VS Code 或云同步盘）更新。为防止直接覆盖外部改动，本次保存已暂停。
        </p>
        <div style="font-size:12.5px;line-height:1.6;color:var(--text-secondary);background:var(--bg-elevated);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);padding:10px 12px">
          <div>• <strong>智能合并并保存（推荐）</strong>：按条目 ID 自动保留外部新增/修改的其他账号，同时写入您本次修改。</div>
          <div>• <strong>强制覆盖文件</strong>：先将外部版本自动备份至 <code>.vault_backups/</code>，再写入当前窗口数据。</div>
          <div>• <strong>重新加载外部版本</strong>：放弃本次未落盘修改，同步读取磁盘最新文件。</div>
        </div>
      `,
      footerButtons: [
        {
          label: "重新加载外部版本",
          className: "btn-ghost",
          onClick: async () => {
            closeModal();
            const res = await api().reload_from_disk();
            if (res.ok) {
              showToast("已重新加载外部最新 .md 文件内容", "info");
              applyUnlockedState(res, state.selectedId);
            } else {
              showToast(res.error || "重新加载失败", "error");
            }
          },
        },
        {
          label: "强制覆盖文件",
          className: "btn-danger-ghost",
          onClick: async () => {
            closeModal();
            await retryWithMode("overwrite");
          },
        },
        {
          label: "智能合并并保存",
          className: "btn-primary",
          onClick: async () => {
            closeModal();
            await retryWithMode("merge");
          },
        },
      ],
    });
  }

  // ==================== BOOT & AUTH ====================
  function syncThemeLabel() {
    const labelEl = $("settings-theme-label");
    if (labelEl) {
      const cur = document.documentElement.getAttribute("data-theme") || "dark";
      labelEl.textContent = cur === "light" ? "浅色" : "深色";
    }
  }

  function closeSettingsPopover() {
    const pop = $("settings-popover");
    const btn = $("btn-sidebar-settings");
    if (pop) pop.classList.add("hidden");
    if (btn) btn.classList.remove("active");
  }

  function renderUpdateIndicators() {
    const verText = `v${state.appVersion || "0.2.1"}`;
    const authBtn = $("btn-auth-update");
    const menuBadge = $("topbar-update-label");
    const sidebarBadge = $("sidebar-version-badge");
    const hasUpd = Boolean(state.updateInfo && state.updateInfo.has_update);

    if (authBtn) {
      authBtn.classList.toggle("has-update", hasUpd);
      authBtn.textContent = hasUpd
        ? `⬆ 新版 v${state.updateInfo.latest_version}`
        : verText;
      authBtn.title = hasUpd
        ? `发现新版本 v${state.updateInfo.latest_version}，点击一键更新`
        : `当前版本 ${verText} · 点击检查软件更新`;
    }

    if (menuBadge) {
      menuBadge.classList.toggle("has-update", hasUpd);
      menuBadge.textContent = hasUpd
        ? `⬆ v${state.updateInfo.latest_version}`
        : verText;
    }

    if (sidebarBadge) {
      sidebarBadge.classList.toggle("has-update", hasUpd);
      sidebarBadge.textContent = hasUpd
        ? `⬆ 新版 v${state.updateInfo.latest_version}`
        : verText;
    }
  }

  async function runSilentStartupUpdateCheck() {
    if (state.startupUpdateChecked || !state.autoCheckUpdates) return;
    state.startupUpdateChecked = true;
    try {
      const res = await api().check_app_update();
      if (res && res.ok) {
        state.updateInfo = res;
        renderUpdateIndicators();
        if (res.has_update) {
          showToast(
            `发现新版本 v${res.latest_version}，可在左下角「设置」中一键更新`,
            "success"
          );
        }
      }
    } catch (_) {
      // Silent background check: ignore offline errors
    }
  }

  async function refreshBootStatus() {
    try {
      const status = await api().get_status();
      if (status.app_version) state.appVersion = status.app_version;
      if (typeof status.auto_check_updates === "boolean") {
        state.autoCheckUpdates = status.auto_check_updates;
      }
      renderAuthStatus(status);
      renderUpdateIndicators();
      if (state.autoCheckUpdates && !state.startupUpdateChecked) {
        setTimeout(runSilentStartupUpdateCheck, 1200);
      }
    } catch (err) {
      showToast("初始化状态读取失败: " + err.message, "error");
    }
  }

  function renderAuthStatus(status) {
    if (status.app_version) state.appVersion = status.app_version;
    if (typeof status.auto_check_updates === "boolean") {
      state.autoCheckUpdates = status.auto_check_updates;
    }
    if (typeof status.auto_lock_minutes === "number") {
      state.autoLockMinutes = status.auto_lock_minutes;
    }
    if (typeof status.lock_on_minimize === "boolean") {
      state.lockOnMinimize = status.lock_on_minimize;
    }
    state.vaultPath = status.vault_path || "";
    state.vaultName = status.vault_name || "我的账号密码库";
    $("auth-vault-path").textContent = state.vaultPath;
    renderUpdateIndicators();
    syncAutoLockLabel();

    $("auth-screen").classList.remove("hidden");
    $("app-workspace").classList.add("hidden");
    $("unlock-error").classList.add("hidden");
    $("create-error").classList.add("hidden");

    if (status.exists) {
      $("unlock-form").classList.remove("hidden");
      $("create-form").classList.add("hidden");
      $("unlock-vault-name").textContent = state.vaultName;
      $("unlock-password").value = "";
      setTimeout(() => $("unlock-password").focus(), 60);
    } else {
      $("unlock-form").classList.add("hidden");
      $("create-form").classList.remove("hidden");
      $("create-password").value = "";
      $("create-password-confirm").value = "";
      if ($("create-pwd-meter")) $("create-pwd-meter").classList.add("hidden");
      setTimeout(() => $("create-password").focus(), 60);
    }
  }

  function applyUnlockedState(res, preferredId = null) {
    if (res.app_version) state.appVersion = res.app_version;
    if (typeof res.auto_check_updates === "boolean") {
      state.autoCheckUpdates = res.auto_check_updates;
    }
    if (typeof res.auto_lock_minutes === "number") {
      state.autoLockMinutes = res.auto_lock_minutes;
    }
    if (typeof res.lock_on_minimize === "boolean") {
      state.lockOnMinimize = res.lock_on_minimize;
    }
    state.lastActivityAt = Date.now();
    state.vaultName = res.vault_name || "我的账号密码库";
    state.vaultPath = res.vault_path || "";
    state.categories = res.categories || [];
    state.entries = res.entries || [];
    state.tagCounts = res.tag_counts || {};
    state.savedTags = res.saved_tags || {};
    state.healthReport = null;
    renderUpdateIndicators();
    syncAutoLockLabel();

    $("auth-screen").classList.add("hidden");
    $("app-workspace").classList.remove("hidden");
    $("header-vault-name").textContent = state.vaultName;
    $("header-vault-path").textContent = state.vaultPath;

    if (res.external_changed) {
      $("btn-sync-external").classList.remove("hidden");
    } else {
      $("btn-sync-external").classList.add("hidden");
    }

    if (res.auto_sealed) {
      showToast("已识别外部编辑器填写的明文凭据，并自动使用 AES-256-GCM 加密落盘", "success");
    }

    if (preferredId && state.entries.some((e) => e.id === preferredId)) {
      state.selectedId = preferredId;
      if (state.filterType === "health") state.filterType = "all";
    } else if (!state.selectedId || !state.entries.some((e) => e.id === state.selectedId)) {
      const visible = getFilteredEntries();
      state.selectedId = visible.length > 0 ? visible[0].id : null;
    }

    state.mode = "view";
    state.revealedSecrets.clear();
    stopTotpTimer();
    renderWorkspace();
  }

  // ==================== FILTERING & RENDERING ====================
  function getFilteredEntries() {
    const q = state.searchQuery.trim().toLowerCase();
    return state.entries.filter((entry) => {
      if (state.filterType === "favorite" && !entry.favorite) return false;
      if (state.filterType === "category" && entry.category !== state.filterCategory) return false;
      if (state.filterTag && !(entry.tags || []).includes(state.filterTag)) return false;

      if (q) {
        const hay = [
          entry.title,
          entry.category,
          entry.platform,
          entry.username,
          entry.phone,
          entry.recovery_email,
          entry.url,
          entry.notes,
          ...(entry.tags || []),
        ]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function renderWorkspace() {
    renderSidebar();
    renderAccountList();
    renderRightPane();
  }

  function syncHealthSidebarBadge() {
    const badge = $("count-health");
    if (!badge) return;
    if (!state.healthReport || !state.healthReport.summary) {
      badge.classList.add("hidden");
      return;
    }
    const issues = Number(state.healthReport.summary.total_issues) || 0;
    badge.textContent = String(issues);
    badge.classList.remove("hidden");
    badge.classList.toggle("warn", issues > 0);
  }

  function renderSidebar() {
    $("count-all").textContent = state.entries.length;
    $("count-fav").textContent = state.entries.filter((e) => e.favorite).length;
    syncHealthSidebarBadge();

    document.querySelectorAll("#quick-nav-list .nav-item").forEach((li) => {
      const ft = li.getAttribute("data-filter-type");
      li.classList.toggle("active", state.filterType === ft);
    });

    // Category counts
    const catCountMap = {};
    state.entries.forEach((e) => {
      catCountMap[e.category] = (catCountMap[e.category] || 0) + 1;
    });

    const catUl = $("category-nav-list");
    catUl.innerHTML = "";
    state.categories.forEach((cat) => {
      const li = document.createElement("li");
      const isActive = state.filterType === "category" && state.filterCategory === cat;
      li.className = `nav-item${isActive ? " active" : ""}`;
      li.innerHTML = `
        <span class="nav-label" title="${escapeHtml(cat)}">📁 ${escapeHtml(cat)}</span>
        <div class="nav-right-group">
          <span class="cat-ops">
            <button type="button" class="cat-op-btn" data-action="rename" title="重命名分类">✎</button>
            <button type="button" class="cat-op-btn" data-action="delete" title="删除分类">🗑</button>
          </span>
          <span class="nav-count">${catCountMap[cat] || 0}</span>
        </div>
      `;
      li.addEventListener("click", (ev) => {
        const actionBtn = ev.target.closest(".cat-op-btn");
        if (actionBtn) {
          ev.stopPropagation();
          const act = actionBtn.getAttribute("data-action");
          if (act === "rename") openRenameCategoryModal(cat);
          if (act === "delete") openDeleteCategoryModal(cat, catCountMap[cat] || 0);
          return;
        }
        state.filterType = "category";
        state.filterCategory = cat;
        state.filterTag = "";
        const filtered = getFilteredEntries();
        if (!filtered.some((e) => e.id === state.selectedId)) {
          state.selectedId = filtered.length ? filtered[0].id : null;
        }
        if (state.mode === "view") {
          state.revealedSecrets.clear();
          stopTotpTimer();
        }
        renderWorkspace();
      });
      catUl.appendChild(li);
    });

    // Scoped Tag Cloud: only load tags belonging to the currently selected category / view
    let scopedEntries = state.entries;
    const tagsTitleEl = $("sidebar-tags-title");
    if (state.filterType === "category") {
      scopedEntries = state.entries.filter((e) => e.category === state.filterCategory);
      if (tagsTitleEl) tagsTitleEl.textContent = "当前分类标签";
    } else if (state.filterType === "favorite") {
      scopedEntries = state.entries.filter((e) => e.favorite);
      if (tagsTitleEl) tagsTitleEl.textContent = "星标账号标签";
    } else {
      if (tagsTitleEl) tagsTitleEl.textContent = "快捷筛选标签";
    }

    const scopedTagCounts = {};
    scopedEntries.forEach((e) => {
      (e.tags || []).forEach((t) => {
        scopedTagCounts[t] = (scopedTagCounts[t] || 0) + 1;
      });
    });

    if (state.filterTag && !scopedTagCounts[state.filterTag]) {
      state.filterTag = "";
    }

    const tagCloud = $("sidebar-tag-cloud");
    tagCloud.innerHTML = "";
    const tagEntries = Object.entries(scopedTagCounts);
    $("btn-clear-tag").classList.toggle("hidden", !state.filterTag);

    if (tagEntries.length === 0) {
      tagCloud.innerHTML = `<span style="font-size:12px;color:var(--text-muted)">当前分类暂无标签</span>`;
    } else {
      tagEntries.forEach(([tag, cnt]) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = `tag-pill${state.filterTag === tag ? " active" : ""}`;
        btn.textContent = `${tag} · ${cnt}`;
        btn.addEventListener("click", () => {
          if (state.filterType === "health") state.filterType = "all";
          state.filterTag = state.filterTag === tag ? "" : tag;
          const filtered = getFilteredEntries();
          if (!filtered.some((e) => e.id === state.selectedId)) {
            state.selectedId = filtered.length ? filtered[0].id : null;
          }
          renderWorkspace();
        });
        tagCloud.appendChild(btn);
      });
    }
  }

  function renderAccountList() {
    const filtered = getFilteredEntries();
    let label = "全部账号";
    if (state.filterType === "favorite") label = "⭐ 星标常用";
    if (state.filterType === "health") label = "🛡 安全体检 · 全部账号";
    if (state.filterType === "category") label = `📁 ${state.filterCategory}`;
    if (state.filterTag) label += ` · #${state.filterTag}`;
    $("list-filter-label").textContent = label;
    $("list-result-count").textContent = `${filtered.length} 条记录`;

    const listEl = $("account-list");
    listEl.innerHTML = "";

    if (filtered.length === 0) {
      listEl.innerHTML = `
        <div class="list-empty-hint">
          当前筛选下没有匹配的账号记录<br/>
          点击右上角 <strong>+ 新建账号</strong> 添加
        </div>
      `;
      return;
    }

    filtered.forEach((entry) => {
      const card = document.createElement("div");
      const isSelected = state.filterType !== "health" && entry.id === state.selectedId;
      card.className = `account-card${isSelected ? " active" : ""}`;
      const tagsHtml = (entry.tags || [])
        .slice(0, 4)
        .map((t) => `<span class="mini-tag">${escapeHtml(t)}</span>`)
        .join("");

      card.innerHTML = `
        <div class="card-avatar">${escapeHtml(pickAvatarLabel(entry))}</div>
        <div class="card-main">
          <div class="card-title-row">
            <span class="card-title">${escapeHtml(entry.title)}</span>
            ${entry.favorite ? '<span class="card-star">⭐</span>' : ""}
          </div>
          <div class="card-username">${escapeHtml(entry.username || entry.platform || entry.category)}</div>
          ${tagsHtml ? `<div class="card-tags">${tagsHtml}</div>` : ""}
        </div>
      `;
      card.addEventListener("click", () => {
        if (state.filterType === "health") {
          state.filterType = "all";
          renderSidebar();
        }
        state.selectedId = entry.id;
        state.mode = "view";
        state.revealedSecrets.clear();
        stopTotpTimer();
        renderAccountList();
        renderRightPane();
      });
      listEl.appendChild(card);
    });
  }

  async function openEditorById(entryId, isDuplicate = false, focusFieldId = "field-title") {
    const res = await api().get_entry_for_edit(entryId);
    if (!res || !res.ok || !res.entry) {
      showToast((res && res.error) || "读取账号加密详情失败", "error");
      return;
    }
    openEditor(res.entry, isDuplicate, focusFieldId);
    if (isDuplicate) {
      showToast("已解密并复制当前账号内容，修改差异项后点击保存即可创建", "info");
    }
  }

  async function renderHealthDashboard(forceRefresh = false) {
    const healthEl = $("health-view");
    if (!healthEl) return;

    if (forceRefresh || !state.healthReport) {
      healthEl.innerHTML = `<div style="padding:28px;color:var(--text-muted);font-size:13.5px">正在本地离线分析密码熵值、复用特征与 2FA 覆盖率...</div>`;
      const res = await api().get_password_health_report(180);
      if (!res || !res.ok || !res.report) {
        healthEl.innerHTML = `<div class="form-error">${escapeHtml(
          (res && res.error) || "密码安全体检失败"
        )}</div>`;
        return;
      }
      state.healthReport = res.report;
      syncHealthSidebarBadge();
    }

    const rpt = state.healthReport;
    const sum = rpt.summary || {};
    const score = Number(rpt.score) || 0;
    const scoreColor =
      score >= 85 ? "var(--success)" : score >= 60 ? "var(--warning)" : "var(--danger)";
    const scoreDesc =
      score >= 85
        ? "整体凭据健康状况良好，请继续保持独立强密码与双重认证习惯。"
        : score >= 60
        ? "存在部分复用密码或弱口令风险，建议优先处理下方高危提醒。"
        : "检测到较多共用密码或高危弱口令，建议立即逐项使用密码生成器更换。";

    const reusedHtml =
      (rpt.reused_groups || []).length === 0
        ? `<div class="health-issue-row"><span style="font-size:12.5px;color:var(--success)">✅ 未发现多账号共用同一密码</span></div>`
        : (rpt.reused_groups || [])
            .map(
              (grp) => `
              <div class="health-cluster-box">
                <span class="health-cluster-badge">同一密码被 ${grp.count} 个账号共用</span>
                ${(grp.entries || [])
                  .map(
                    (it) => `
                    <div class="health-issue-row" style="padding-left:0;padding-right:0">
                      <div class="health-issue-main">
                        <div class="health-issue-title">${escapeHtml(it.title)}</div>
                        <div class="health-issue-sub">${escapeHtml(it.category)}${
                      it.username ? ` · ${escapeHtml(it.username)}` : ""
                    }</div>
                      </div>
                      <div class="field-ops">
                        <button type="button" class="btn btn-ghost btn-xs btn-health-view" data-id="${escapeHtml(
                          it.id
                        )}">查看</button>
                        <button type="button" class="btn btn-primary btn-xs btn-health-edit" data-id="${escapeHtml(
                          it.id
                        )}">去改密</button>
                      </div>
                    </div>`
                  )
                  .join("")}
              </div>`
            )
            .join("");

    const weakHtml =
      (rpt.weak_entries || []).length === 0
        ? `<div class="health-issue-row"><span style="font-size:12.5px;color:var(--success)">✅ 未发现弱口令或过短密码</span></div>`
        : (rpt.weak_entries || [])
            .map(
              (it) => `
              <div class="health-issue-row">
                <div class="health-issue-main">
                  <div class="health-issue-title">${escapeHtml(it.title)} <span style="font-size:11.5px;color:var(--danger);font-weight:500">· ${escapeHtml(
                it.strength_label
              )} (${it.length} 位)</span></div>
                  <div class="health-issue-sub">${escapeHtml(
                    (it.reasons || []).join("；") || "建议提升密码长度与字符复杂度"
                  )}</div>
                </div>
                <div class="field-ops">
                  <button type="button" class="btn btn-ghost btn-xs btn-health-view" data-id="${escapeHtml(
                    it.id
                  )}">查看</button>
                  <button type="button" class="btn btn-primary btn-xs btn-health-edit" data-id="${escapeHtml(
                    it.id
                  )}">去改密</button>
                </div>
              </div>`
            )
            .join("");

    const no2faHtml =
      (rpt.unprotected_2fa_entries || []).length === 0
        ? `<div class="health-issue-row"><span style="font-size:12.5px;color:var(--success)">✅ 所有已设密账号均已记录 TOTP 动态码或 2FA 恢复码</span></div>`
        : (rpt.unprotected_2fa_entries || [])
            .map(
              (it) => `
              <div class="health-issue-row">
                <div class="health-issue-main">
                  <div class="health-issue-title">${escapeHtml(it.title)}</div>
                  <div class="health-issue-sub">${escapeHtml(it.category)}${
                it.username ? ` · ${escapeHtml(it.username)}` : ""
              } · 未绑定 TOTP 或 2FA 恢复码</div>
                </div>
                <div class="field-ops">
                  <button type="button" class="btn btn-ghost btn-xs btn-health-edit" data-id="${escapeHtml(
                    it.id
                  )}">补充 2FA</button>
                </div>
              </div>`
            )
            .join("");

    const staleHtml =
      (rpt.stale_entries || []).length === 0
        ? `<div class="health-issue-row"><span style="font-size:12.5px;color:var(--success)">✅ 暂无超过 ${
            rpt.stale_threshold_days || 180
          } 天未更新的密码记录</span></div>`
        : (rpt.stale_entries || [])
            .map(
              (it) => `
              <div class="health-issue-row">
                <div class="health-issue-main">
                  <div class="health-issue-title">${escapeHtml(it.title)}</div>
                  <div class="health-issue-sub">距上次更新已 ${it.age_days} 天（${escapeHtml(
                it.updated_at
              )}）</div>
                </div>
                <div class="field-ops">
                  <button type="button" class="btn btn-ghost btn-xs btn-health-edit" data-id="${escapeHtml(
                    it.id
                  )}">轮换密码</button>
                </div>
              </div>`
            )
            .join("");

    healthEl.innerHTML = `
      <div class="detail-top">
        <div>
          <div class="detail-breadcrumb">🛡 纯本地离线安全审计 · 零联网零上传</div>
          <h2 class="detail-title">账号密码安全体检报告</h2>
        </div>
        <div class="detail-actions">
          <button type="button" class="btn btn-ghost btn-sm" id="btn-health-refresh">↻ 重新扫描</button>
        </div>
      </div>

      <div class="health-hero">
        <div>
          <div style="font-size:12.5px;color:var(--text-secondary);margin-bottom:4px">密码库综合安全评分（共检测 ${
            sum.total_entries || 0
          } 条账号）</div>
          <div style="font-size:13px;color:var(--text-primary);line-height:1.5">${escapeHtml(
            scoreDesc
          )}</div>
        </div>
        <div class="health-score-box">
          <span class="health-score-num" style="color:${scoreColor}">${score}</span>
          <span class="health-score-unit">/ 100 分</span>
        </div>
      </div>

      <div class="health-stats-grid">
        <div class="health-stat-card">
          <div class="health-stat-val" style="color:${
            sum.reused_entry_count > 0 ? "var(--danger)" : "var(--success)"
          }">${sum.reused_entry_count || 0}</div>
          <div class="health-stat-label">重复共用密码账号</div>
        </div>
        <div class="health-stat-card">
          <div class="health-stat-val" style="color:${
            sum.weak_count > 0 ? "var(--danger)" : "var(--success)"
          }">${sum.weak_count || 0}</div>
          <div class="health-stat-label">弱口令 / 长度不足</div>
        </div>
        <div class="health-stat-card">
          <div class="health-stat-val" style="color:${
            sum.unprotected_2fa_count > 0 ? "var(--warning)" : "var(--success)"
          }">${sum.unprotected_2fa_count || 0}</div>
          <div class="health-stat-label">未配置 2FA / TOTP</div>
        </div>
        <div class="health-stat-card">
          <div class="health-stat-val" style="color:${
            sum.stale_count > 0 ? "var(--warning)" : "var(--success)"
          }">${sum.stale_count || 0}</div>
          <div class="health-stat-label">超 180 天未更新</div>
        </div>
      </div>

      <div class="info-panel">
        <div class="info-panel-header"><span>🚨 重复共用密码（高危：一处撞库危及多处）</span></div>
        ${reusedHtml}
      </div>

      <div class="info-panel">
        <div class="info-panel-header"><span>⚠️ 弱口令与高风险密码</span></div>
        ${weakHtml}
      </div>

      <div class="info-panel">
        <div class="info-panel-header"><span>🔐 未记录双重认证 (TOTP / 2FA 恢复码)</span></div>
        ${no2faHtml}
      </div>

      <div class="info-panel">
        <div class="info-panel-header"><span>⏳ 长期未轮换密码记录</span></div>
        ${staleHtml}
      </div>
    `;

    const refreshBtn = $("btn-health-refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => renderHealthDashboard(true));
    }

    healthEl.querySelectorAll(".btn-health-view").forEach((btn) => {
      btn.addEventListener("click", () => {
        const targetId = btn.getAttribute("data-id");
        state.selectedId = targetId;
        state.filterType = "all";
        state.mode = "view";
        state.revealedSecrets.clear();
        stopTotpTimer();
        renderWorkspace();
      });
    });

    healthEl.querySelectorAll(".btn-health-edit").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const targetId = btn.getAttribute("data-id");
        state.selectedId = targetId;
        await openEditorById(targetId, false);
      });
    });
  }

  function renderRightPane() {
    const emptyEl = $("detail-empty");
    const viewEl = $("detail-view");
    const healthEl = $("health-view");
    const editorEl = $("entry-editor");

    if (state.mode === "edit") {
      stopTotpTimer();
      emptyEl.classList.add("hidden");
      viewEl.classList.add("hidden");
      if (healthEl) healthEl.classList.add("hidden");
      editorEl.classList.remove("hidden");
      return;
    }

    editorEl.classList.add("hidden");

    if (state.filterType === "health") {
      stopTotpTimer();
      emptyEl.classList.add("hidden");
      viewEl.classList.add("hidden");
      if (healthEl) {
        healthEl.classList.remove("hidden");
        renderHealthDashboard(false);
      }
      return;
    }

    if (healthEl) healthEl.classList.add("hidden");

    const entry = state.entries.find((e) => e.id === state.selectedId);
    if (!entry) {
      stopTotpTimer();
      emptyEl.classList.remove("hidden");
      viewEl.classList.add("hidden");
      return;
    }

    emptyEl.classList.add("hidden");
    viewEl.classList.remove("hidden");

    const hasPassword = Boolean(entry.has_password || entry.password);
    const hasTotp = Boolean(entry.has_totp);
    const hasTwoFa = Boolean(entry.has_two_fa || entry.two_fa_recovery);

    const isPwdShown = state.revealedSecrets.has("password");
    const isTotpSeedShown = state.revealedSecrets.has("totp_secret");
    const is2faShown = state.revealedSecrets.has("2fa");

    const tagsRowHtml =
      entry.tags && entry.tags.length
        ? `<div class="detail-tags-bar">${entry.tags
            .map((t) => `<span class="detail-tag-chip"># ${escapeHtml(t)}</span>`)
            .join("")}</div>`
        : "";

    const customRowsHtml = Object.entries(entry.custom_fields || {})
      .map(
        ([k, v]) => `
        <div class="field-row">
          <div class="field-meta">
            <div class="field-label">${escapeHtml(k)}</div>
            <div class="field-value selectable">${escapeHtml(v)}</div>
          </div>
          <div class="field-ops">
            <button type="button" class="btn btn-ghost btn-xs copy-trigger" data-copy="${escapeHtml(v)}" data-secret="0">复制</button>
          </div>
        </div>`
      )
      .join("");

    const cachedTotp =
      state.totpState && state.totpState.entryId === entry.id ? state.totpState : null;
    const showLiveTotp = Boolean(
      hasTotp || (cachedTotp && !cachedTotp.noTotp && (cachedTotp.code || cachedTotp.error))
    );

    const totpRowHtml = showLiveTotp
      ? `
        <div class="field-row" id="totp-live-row">
          <div class="field-meta">
            <div class="field-label">双重认证动态验证码 (TOTP · RFC 6238)</div>
            <div class="totp-live-wrap">
              <span class="totp-code-display selectable" id="totp-code-val">••• •••</span>
              <span class="totp-countdown-pill" id="totp-countdown-val">计算中...</span>
            </div>
            <div class="totp-progress-track">
              <div class="totp-progress-fill" id="totp-progress-fill" style="width:100%"></div>
            </div>
            ${
              isTotpSeedShown
                ? `<div class="field-value mono selectable" style="margin-top:6px;font-size:12px;color:var(--text-secondary)">密钥种子：${escapeHtml(
                    state.revealedSecrets.get("totp_secret")
                  )}</div>`
                : ""
            }
          </div>
          <div class="field-ops">
            <button type="button" class="btn btn-ghost btn-xs reveal-trigger" data-field-key="totp_secret">${
              isTotpSeedShown ? "隐藏密钥" : "显示密钥"
            }</button>
            <button type="button" class="btn btn-primary btn-xs" id="btn-copy-totp">复制动态码</button>
          </div>
        </div>
      `
      : "";

    const hasSecurity =
      (entry.security_questions && entry.security_questions.length > 0) || hasTwoFa;

    let securityPanelHtml = "";
    if (hasSecurity) {
      const qaHtml = (entry.security_questions || [])
        .map((qa, idx) => {
          const key = `qa_${idx}`;
          const hasAns = Boolean(qa.has_answer || qa.answer);
          const shown = state.revealedSecrets.has(key);
          return `
            <div class="field-row">
              <div class="field-meta">
                <div class="field-label">密保问题 ${idx + 1}：${escapeHtml(qa.question)}</div>
                <div class="field-value mono selectable">${
                  hasAns
                    ? shown
                      ? escapeHtml(state.revealedSecrets.get(key))
                      : "••••••••••••"
                    : "<span style='color:var(--text-muted)'>未填写答案</span>"
                }</div>
              </div>
              ${
                hasAns
                  ? `<div class="field-ops">
                      <button type="button" class="btn btn-ghost btn-xs reveal-trigger" data-field-key="${key}">${shown ? "隐藏" : "显示"}</button>
                      <button type="button" class="btn btn-ghost btn-xs secret-copy-trigger" data-field-key="${key}">复制答案</button>
                    </div>`
                  : ""
              }
            </div>
          `;
        })
        .join("");

      const twoFaHtml = hasTwoFa
        ? `
          <div class="field-row">
            <div class="field-meta">
              <div class="field-label">2FA 密钥 / 备用恢复码（AES-256-GCM 绑定上下文加密）</div>
              <div class="field-value mono selectable" style="white-space:pre-wrap">${
                is2faShown ? escapeHtml(state.revealedSecrets.get("2fa")) : "••••-••••-••••-••••"
              }</div>
            </div>
            <div class="field-ops">
              <button type="button" class="btn btn-ghost btn-xs reveal-trigger" data-field-key="2fa">${is2faShown ? "隐藏" : "显示"}</button>
              <button type="button" class="btn btn-ghost btn-xs secret-copy-trigger" data-field-key="2fa">复制恢复码</button>
            </div>
          </div>
        `
        : "";

      securityPanelHtml = `
        <div class="info-panel">
          <div class="info-panel-header">
            <span>🛡 密保问题与双重认证恢复信息</span>
          </div>
          ${qaHtml}
          ${twoFaHtml}
        </div>
      `;
    }

    const notesPanelHtml = entry.notes
      ? `
        <div class="info-panel">
          <div class="info-panel-header"><span>📝 备注说明</span></div>
          <div class="notes-body selectable">${escapeHtml(entry.notes)}</div>
        </div>
      `
      : "";

    viewEl.innerHTML = `
      <div class="detail-top">
        <div>
          <div class="detail-breadcrumb">📁 ${escapeHtml(entry.category)}${
            entry.platform ? ` · ${escapeHtml(entry.platform)}` : ""
          }</div>
          <h2 class="detail-title selectable">${escapeHtml(entry.title)}</h2>
        </div>
        <div class="detail-actions">
          <button type="button" class="btn btn-ghost btn-sm" id="btn-detail-fav" title="切换星标">
            <svg viewBox="0 0 24 24" fill="${entry.favorite ? "currentColor" : "none"}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
            <span>${entry.favorite ? "已星标" : "星标"}</span>
          </button>
          <button type="button" class="btn btn-ghost btn-sm" id="btn-detail-duplicate" title="基于此账号复制新建一条记录">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            <span>复制账号</span>
          </button>
          <button type="button" class="btn btn-primary btn-sm" id="btn-detail-edit">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
            <span>编辑</span>
          </button>
          <button type="button" class="btn btn-danger-ghost btn-sm" id="btn-detail-delete">删除</button>
        </div>
      </div>

      ${tagsRowHtml}

      <div class="info-panel">
        <div class="info-panel-header"><span>🔑 登录凭据与绑定信息</span></div>
        ${
          entry.username
            ? `<div class="field-row">
                <div class="field-meta">
                  <div class="field-label">登录账号 / 用户名</div>
                  <div class="field-value mono selectable">${escapeHtml(entry.username)}</div>
                </div>
                <div class="field-ops">
                  <button type="button" class="btn btn-ghost btn-xs copy-trigger" data-copy="${escapeHtml(entry.username)}" data-secret="0">复制账号</button>
                </div>
              </div>`
            : ""
        }
        <div class="field-row">
          <div class="field-meta">
            <div class="field-label">登录密码（按需解密 · AES-256-GCM 上下文绑定加密）</div>
            <div class="field-value mono selectable">${
              hasPassword
                ? isPwdShown
                  ? escapeHtml(state.revealedSecrets.get("password"))
                  : "••••••••••••••••"
                : "<span style='color:var(--text-muted)'>未设置密码</span>"
            }</div>
          </div>
          ${
            hasPassword
              ? `<div class="field-ops">
                  <button type="button" class="btn btn-ghost btn-xs reveal-trigger" data-field-key="password">${isPwdShown ? "隐藏" : "显示"}</button>
                  <button type="button" class="btn btn-primary btn-xs secret-copy-trigger" data-field-key="password">复制密码</button>
                </div>`
              : ""
          }
        </div>
        ${totpRowHtml}
        ${
          entry.phone
            ? `<div class="field-row">
                <div class="field-meta">
                  <div class="field-label">绑定手机号</div>
                  <div class="field-value mono selectable">${escapeHtml(entry.phone)}</div>
                </div>
                <div class="field-ops">
                  <button type="button" class="btn btn-ghost btn-xs copy-trigger" data-copy="${escapeHtml(entry.phone)}" data-secret="0">复制</button>
                </div>
              </div>`
            : ""
        }
        ${
          entry.recovery_email
            ? `<div class="field-row">
                <div class="field-meta">
                  <div class="field-label">辅助 / 恢复邮箱</div>
                  <div class="field-value mono selectable">${escapeHtml(entry.recovery_email)}</div>
                </div>
                <div class="field-ops">
                  <button type="button" class="btn btn-ghost btn-xs copy-trigger" data-copy="${escapeHtml(entry.recovery_email)}" data-secret="0">复制</button>
                </div>
              </div>`
            : ""
        }
        ${
          entry.url
            ? `<div class="field-row">
                <div class="field-meta">
                  <div class="field-label">服务网址 / 登录入口</div>
                  <div class="field-value selectable">
                    <button type="button" class="url-inline-link open-url-trigger" data-url="${escapeHtml(entry.url)}" title="点击在默认浏览器中打开">${escapeHtml(entry.url)}</button>
                  </div>
                </div>
                <div class="field-ops">
                  <button type="button" class="btn btn-ghost btn-xs copy-trigger" data-copy="${escapeHtml(entry.url)}" data-secret="0">复制链接</button>
                </div>
              </div>`
            : ""
        }
        ${customRowsHtml}
      </div>

      ${securityPanelHtml}
      ${notesPanelHtml}

      <div class="detail-footer-meta">
        记录 ID: <code>${escapeHtml(entry.id)}</code> · 最后更新: ${escapeHtml(entry.updated_at || "-")}
      </div>
    `;

    if (showLiveTotp) {
      if (cachedTotp && (cachedTotp.code || cachedTotp.error)) {
        syncTotpDomElements();
        ensureTotpInterval(entry.id);
      } else {
        startTotpLoop(entry.id);
      }
    } else {
      stopTotpTimer();
    }

    // Bind detail button actions
    $("btn-detail-fav").addEventListener("click", async () => {
      const doToggle = async (mode = "abort") => {
        const res = await api().toggle_favorite(entry.id, mode);
        if (res.conflict) return openConflictModal(doToggle);
        if (res.ok) applyUnlockedState(res, entry.id);
        else showToast(res.error || "更新星标失败", "error");
      };
      await doToggle("abort");
    });

    $("btn-detail-duplicate").addEventListener("click", () => openEditorById(entry.id, true));
    $("btn-detail-edit").addEventListener("click", () => openEditorById(entry.id, false));
    $("btn-detail-delete").addEventListener("click", () => confirmDeleteEntry(entry));

    const copyTotpBtn = $("btn-copy-totp");
    if (copyTotpBtn) {
      copyTotpBtn.addEventListener("click", async () => {
        const res = await api().copy_entry_totp(entry.id, 30);
        if (res && res.ok) {
          showToast("6 位动态验证码已复制（已屏蔽剪贴板历史，30 秒后自动清空）", "success");
        } else {
          showToast((res && res.error) || "复制动态码失败", "error");
        }
      });
    }

    viewEl.querySelectorAll(".open-url-trigger").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const targetUrl = btn.getAttribute("data-url");
        const res = await api().open_external_url(targetUrl);
        if (res.ok) {
          showToast("已在系统浏览器中打开链接", "info");
        } else {
          showToast(res.error || "无法打开该链接", "error");
        }
      });
    });

    viewEl.querySelectorAll(".reveal-trigger").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const key = btn.getAttribute("data-field-key");
        if (state.revealedSecrets.has(key)) {
          state.revealedSecrets.delete(key);
          renderRightPane();
          return;
        }
        const res = await api().reveal_entry_secret(entry.id, key);
        if (res && res.ok) {
          state.revealedSecrets.set(key, res.value || "");
          renderRightPane();
        } else {
          showToast((res && res.error) || "解密失败", "error");
        }
      });
    });

    viewEl.querySelectorAll(".secret-copy-trigger").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const key = btn.getAttribute("data-field-key");
        const res = await api().copy_entry_secret(entry.id, key, 30);
        if (res && res.ok) {
          showToast("敏感凭据已直接从后端复制（不经前端缓存，30 秒后自动清空）", "success");
        } else {
          showToast((res && res.error) || "复制失败", "error");
        }
      });
    });

    viewEl.querySelectorAll(".copy-trigger").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const val = btn.getAttribute("data-copy");
        const res = await api().copy_to_clipboard(val, 0, false);
        if (res.ok) {
          showToast("已复制到剪贴板", "success");
        } else {
          showToast(res.error || "复制失败", "error");
        }
      });
    });
  }

  // ==================== EDITOR FORM ====================
  function populateCategorySelect(selectedCat) {
    const sel = $("field-category");
    sel.innerHTML = "";
    const cats = state.categories.length ? [...state.categories] : ["开发与云服务", "工作与个人邮箱", "未分类"];
    if (selectedCat && !cats.includes(selectedCat)) cats.push(selectedCat);
    cats.forEach((c) => {
      const opt = document.createElement("option");
      opt.value = c;
      opt.textContent = c;
      if (c === selectedCat) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  function addQaRow(question = "", answer = "") {
    const container = $("qa-rows-container");
    const row = document.createElement("div");
    row.className = "qa-edit-row";
    row.innerHTML = `
      <input type="text" class="qa-q-input" placeholder="密保问题（例如：你少年时代最好的朋友叫什么名字？）" value="${escapeHtml(question)}" />
      <input type="text" class="qa-a-input" placeholder="密保答案（落盘自动加密）" value="${escapeHtml(answer)}" />
      <button type="button" class="icon-btn btn-remove-qa" title="移除此条">✕</button>
    `;
    row.querySelector(".btn-remove-qa").addEventListener("click", () => row.remove());
    container.appendChild(row);
  }

  function parseTagsInput() {
    return $("field-tags")
      .value.replace(/，/g, ",")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function syncPresetTagHighlights() {
    const current = parseTagsInput();
    document.querySelectorAll("#preset-tags-bar .preset-chip").forEach((chip) => {
      const tag = chip.getAttribute("data-tag");
      chip.classList.toggle("selected", current.includes(tag));
    });
  }

  function renderPresetTagsBar() {
    const bar = $("preset-tags-bar");
    if (!bar) return;
    const currentCat = ($("field-category").value || "").trim();
    const savedList = (state.savedTags && state.savedTags[currentCat]) || [];

    bar.innerHTML = `<span class="preset-hint">快捷标签：</span>`;
    if (savedList.length === 0) {
      const emptyHint = document.createElement("span");
      emptyHint.className = "preset-hint";
      emptyHint.textContent = "暂无（上方输入标签后按 Enter 或保存账号即自动记录）";
      bar.appendChild(emptyHint);
      return;
    }

    const activeTags = parseTagsInput();
    savedList.forEach((tag) => {
      const chip = document.createElement("span");
      chip.className = `preset-chip${activeTags.includes(tag) ? " selected" : ""}`;
      chip.setAttribute("data-tag", tag);

      const labelBtn = document.createElement("button");
      labelBtn.type = "button";
      labelBtn.className = "preset-chip-label";
      labelBtn.textContent = tag;
      labelBtn.title = "点击选用或取消该标签";
      labelBtn.addEventListener("click", () => {
        const list = parseTagsInput();
        const idx = list.indexOf(tag);
        if (idx >= 0) list.splice(idx, 1);
        else list.push(tag);
        $("field-tags").value = list.join(", ");
        syncPresetTagHighlights();
      });

      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "preset-chip-del";
      delBtn.textContent = "×";
      delBtn.title = `删除快捷标签「${tag}」`;
      delBtn.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        const doDelTag = async (mode = "abort") => {
          const res = await api().delete_saved_tag(currentCat, tag, mode);
          if (res.conflict) return openConflictModal(doDelTag);
          if (res.ok) {
            state.savedTags = res.saved_tags || {};
            renderPresetTagsBar();
            showToast(`已删除快捷标签「${tag}」`, "info");
          } else {
            showToast(res.error || "删除标签失败", "error");
          }
        };
        await doDelTag("abort");
      });

      chip.appendChild(labelBtn);
      chip.appendChild(delBtn);
      bar.appendChild(chip);
    });
  }

  function openEditor(entry = null, isDuplicate = false, focusFieldId = "field-title") {
    state.mode = "edit";
    const hasSource = Boolean(entry);
    const isEdit = hasSource && !isDuplicate;
    $("editor-heading").textContent = isDuplicate
      ? "复制新建账号"
      : isEdit
      ? "编辑账号记录"
      : "新建账号记录";
    $("field-id").value = isEdit ? entry.id : "";
    $("field-favorite").checked = hasSource ? Boolean(entry.favorite) : false;
    state.editingCustomFields =
      isDuplicate && entry.custom_fields ? { ...entry.custom_fields } : null;

    const defaultCat = hasSource
      ? entry.category
      : state.filterType === "category" && state.filterCategory
      ? state.filterCategory
      : state.categories[0] || "开发与云服务";

    populateCategorySelect(defaultCat);
    $("field-platform").value = hasSource ? entry.platform || "" : "";
    $("field-title").value = hasSource
      ? isDuplicate
        ? `${entry.title} (副本)`
        : entry.title || ""
      : "";
    $("field-tags").value = hasSource ? (entry.tags || []).join(", ") : state.filterTag || "";
    $("field-username").value = hasSource ? entry.username || "" : "";
    $("field-password").value = hasSource ? entry.password || "" : "";
    $("field-password").type = "password";
    $("field-phone").value = hasSource ? entry.phone || "" : "";
    $("field-recovery-email").value = hasSource ? entry.recovery_email || "" : "";
    $("field-url").value = hasSource ? entry.url || "" : "";
    $("field-2fa").value = hasSource ? entry.two_fa_recovery || entry.totp_secret || "" : "";
    $("field-notes").value = hasSource ? entry.notes || "" : "";
    $("inline-pwgen-box").classList.add("hidden");

    const qaContainer = $("qa-rows-container");
    qaContainer.innerHTML = "";
    if (hasSource && entry.security_questions && entry.security_questions.length > 0) {
      entry.security_questions.forEach((qa) => addQaRow(qa.question, qa.answer));
    }

    updateEditorTotpPreview();
    renderPresetTagsBar();
    renderRightPane();
    setTimeout(() => {
      const targetEl = $(focusFieldId) || $("field-title");
      if (targetEl) {
        targetEl.focus();
        if (isDuplicate && targetEl === $("field-title")) targetEl.select();
      }
    }, 40);
  }

  function openNotesRiskModal(risks, onConfirmSaveAnyway) {
    const itemsHtml = (risks || [])
      .map((r) => {
        if (typeof r === "string") {
          return `<div class="risk-item"><strong>• ${escapeHtml(r)}</strong></div>`;
        }
        return `
        <div class="risk-item">
          <div><strong>• ${escapeHtml(r.label)}</strong></div>
          <div style="color:var(--text-secondary);margin-top:2px">${escapeHtml(r.detail || "")}</div>
        </div>`;
      })
      .join("");

    openModal({
      title: "⚠️ 备注栏疑似包含高敏感密钥或密码",
      wide: true,
      bodyHtml: `
        <p style="font-size:13px;line-height:1.65;color:var(--text-primary)">
          为了支持在 Obsidian / VS Code 中直接阅读说明，「<strong>备注说明</strong>」字段在本地 <code>.md</code> 文件中是<strong>明文存储</strong>的。系统检测到您在备注中填写了以下疑似敏感凭据：
        </p>
        <div class="risk-list">${itemsHtml}</div>
        <p style="font-size:12.5px;color:var(--text-secondary);line-height:1.55">
          建议将密码、私钥、助记词或恢复密钥移入上方的「<strong>登录密码</strong>」或「<strong>2FA 密钥 / 备用恢复码</strong>」字段（落盘自动执行 AES-256-GCM 加密）。
        </p>
      `,
      footerButtons: [
        {
          label: "返回修改备注（推荐）",
          className: "btn-primary",
          onClick: closeModal,
        },
        {
          label: "知晓风险，仍明文保存",
          className: "btn-danger-ghost",
          onClick: async () => {
            closeModal();
            await onConfirmSaveAnyway();
          },
        },
      ],
    });
  }

  async function submitEditorForm(ev) {
    ev.preventDefault();
    const qaRows = [];
    document.querySelectorAll("#qa-rows-container .qa-edit-row").forEach((row) => {
      const q = row.querySelector(".qa-q-input").value.trim();
      const a = row.querySelector(".qa-a-input").value.trim();
      if (q || a) qaRows.push({ question: q, answer: a });
    });

    const payload = {
      id: $("field-id").value.trim(),
      category: $("field-category").value.trim(),
      platform: $("field-platform").value.trim(),
      title: $("field-title").value.trim(),
      favorite: $("field-favorite").checked,
      tags: $("field-tags").value,
      username: $("field-username").value.trim(),
      password: $("field-password").value,
      totp_secret: "",
      phone: $("field-phone").value.trim(),
      recovery_email: $("field-recovery-email").value.trim(),
      url: $("field-url").value.trim(),
      security_questions: qaRows,
      two_fa_recovery: $("field-2fa").value.trim(),
      notes: $("field-notes").value,
      custom_fields: state.editingCustomFields,
    };

    const doSave = async (mode = "abort", allowRiskyNotes = false) => {
      const res = await api().save_entry(payload, mode, allowRiskyNotes);
      if (res.notes_warning) {
        return openNotesRiskModal(res.risks, () => doSave(mode, true));
      }
      if (res.conflict) {
        return openConflictModal((resolvedMode) => doSave(resolvedMode, allowRiskyNotes));
      }
      if (!res.ok) {
        showToast(res.error || "保存失败", "error");
        return;
      }
      showToast(
        mode === "merge"
          ? "已智能合并外部改动并加密保存至本地 .md 文件"
          : "已加密保存并更新至本地 .md 文件",
        "success"
      );
      applyUnlockedState(res, res.saved_id);
    };

    await doSave("abort", false);
  }

  function confirmDeleteEntry(entry) {
    openModal({
      title: "确认删除账号",
      bodyHtml: `<p style="line-height:1.6">确定要从本地 Markdown 密码库中删除 <strong>${escapeHtml(
        entry.title
      )}</strong> 吗？<br/><span style="font-size:12px;color:var(--text-muted)">删除前系统会自动在 .vault_backups 目录保留分层历史快照。</span></p>`,
      footerButtons: [
        { label: "取消", className: "btn-ghost", onClick: closeModal },
        {
          label: "确认删除",
          className: "btn-danger",
          onClick: async () => {
            closeModal();
            const doDelete = async (mode = "abort") => {
              const res = await api().delete_entry(entry.id, mode);
              if (res.conflict) return openConflictModal(doDelete);
              if (res.ok) {
                showToast("账号记录已删除", "info");
                state.selectedId = null;
                applyUnlockedState(res);
              } else {
                showToast(res.error || "删除失败", "error");
              }
            };
            await doDelete("abort");
          },
        },
      ],
    });
  }

  // ==================== CATEGORY MODALS ====================
  function openAddCategoryModal(onCreatedCallback = null) {
    openModal({
      title: "新建分类目录",
      bodyHtml: `
        <div class="form-group">
          <label>分类名称（对应 Markdown 中的 ## 二级标题）</label>
          <input type="text" id="modal-cat-name" placeholder="例如：游戏平台 / 银行金融 / AI工具" />
        </div>
      `,
      footerButtons: [
        { label: "取消", className: "btn-ghost", onClick: closeModal },
        {
          label: "创建分类",
          className: "btn-primary",
          onClick: async () => {
            const name = $("modal-cat-name").value.trim();
            if (!name) return showToast("请输入分类名称", "error");
            const doAddCat = async (mode = "abort") => {
              const res = await api().add_category(name, mode);
              if (res.conflict) return openConflictModal(doAddCat);
              if (!res.ok) return showToast(res.error, "error");
              closeModal();
              showToast(`已添加分类「${name}」`, "success");
              if (onCreatedCallback) {
                state.categories = res.categories || [];
                onCreatedCallback(name);
                renderSidebar();
              } else {
                state.filterType = "category";
                state.filterCategory = name;
                applyUnlockedState(res, state.selectedId);
              }
            };
            await doAddCat("abort");
          },
        },
      ],
    });
    setTimeout(() => $("modal-cat-name") && $("modal-cat-name").focus(), 50);
  }

  function openRenameCategoryModal(oldName) {
    openModal({
      title: "重命名分类",
      bodyHtml: `
        <div class="form-group">
          <label>将「${escapeHtml(oldName)}」修改为：</label>
          <input type="text" id="modal-rename-cat" value="${escapeHtml(oldName)}" />
        </div>
      `,
      footerButtons: [
        { label: "取消", className: "btn-ghost", onClick: closeModal },
        {
          label: "保存修改",
          className: "btn-primary",
          onClick: async () => {
            const newName = $("modal-rename-cat").value.trim();
            if (!newName) return showToast("分类名称不能为空", "error");
            const doRename = async (mode = "abort") => {
              const res = await api().rename_category(oldName, newName, mode);
              if (res.conflict) return openConflictModal(doRename);
              if (!res.ok) return showToast(res.error, "error");
              closeModal();
              if (state.filterType === "category" && state.filterCategory === oldName) {
                state.filterCategory = newName;
              }
              showToast("分类已重命名", "success");
              applyUnlockedState(res, state.selectedId);
            };
            await doRename("abort");
          },
        },
      ],
    });
    setTimeout(() => $("modal-rename-cat") && $("modal-rename-cat").select(), 50);
  }

  function openDeleteCategoryModal(catName, count) {
    const hint =
      count > 0
        ? `该分类下包含 <strong>${count}</strong> 条账号记录，删除分类后这些账号将自动移入「<strong>未分类</strong>」，数据不会丢失。`
        : `该分类下当前没有账号记录，可直接移除。`;
    openModal({
      title: `移除分类「${catName}」`,
      bodyHtml: `<p style="line-height:1.6">${hint}</p>`,
      footerButtons: [
        { label: "取消", className: "btn-ghost", onClick: closeModal },
        {
          label: "确认移除",
          className: "btn-danger",
          onClick: async () => {
            closeModal();
            const doDelCat = async (mode = "abort") => {
              const res = await api().delete_category(catName, "未分类", mode);
              if (res.conflict) return openConflictModal(doDelCat);
              if (res.ok) {
                if (state.filterType === "category" && state.filterCategory === catName) {
                  state.filterType = "all";
                  state.filterCategory = "";
                }
                showToast(`分类「${catName}」已移除`, "info");
                applyUnlockedState(res, state.selectedId);
              } else {
                showToast(res.error || "操作失败", "error");
              }
            };
            await doDelCat("abort");
          },
        },
      ],
    });
  }

  // ==================== PASSWORD GENERATOR & SETTINGS MODALS ====================
  async function openStandalonePasswordModal() {
    openModal({
      title: "🎲 随机强密码生成器",
      bodyHtml: `
        <div class="pw-preview-box selectable" id="modal-pw-output">生成中...</div>
        <div class="form-group">
          <label>密码长度: <strong id="modal-pw-len-label">20</strong> 位</label>
          <input type="range" id="modal-pw-len" min="8" max="64" value="20" style="width:100%" />
        </div>
        <div class="pwgen-row" style="margin-top:8px">
          <label class="chk-inline"><input type="checkbox" id="m-pw-upper" checked /> 大写字母</label>
          <label class="chk-inline"><input type="checkbox" id="m-pw-lower" checked /> 小写字母</label>
          <label class="chk-inline"><input type="checkbox" id="m-pw-digits" checked /> 数字</label>
          <label class="chk-inline"><input type="checkbox" id="m-pw-symbols" checked /> 特殊符号</label>
          <label class="chk-inline"><input type="checkbox" id="m-pw-noamb" checked /> 排除易混淆字符(0O1lI)</label>
        </div>
      `,
      footerButtons: [
        { label: "关闭", className: "btn-ghost", onClick: closeModal },
        {
          label: "重新生成",
          className: "btn-ghost",
          onClick: () => refreshModalPassword(),
        },
        {
          label: "复制密码",
          className: "btn-primary",
          onClick: async () => {
            const val = $("modal-pw-output").textContent;
            await api().copy_to_clipboard(val, 30, true);
            showToast("强密码已复制（已屏蔽剪贴板历史，30 秒后自动清空）", "success");
          },
        },
      ],
    });

    async function refreshModalPassword() {
      const len = parseInt($("modal-pw-len").value, 10);
      $("modal-pw-len-label").textContent = len;
      const res = await api().generate_random_password({
        length: len,
        use_upper: $("m-pw-upper").checked,
        use_lower: $("m-pw-lower").checked,
        use_digits: $("m-pw-digits").checked,
        use_symbols: $("m-pw-symbols").checked,
        exclude_ambiguous: $("m-pw-noamb").checked,
      });
      if (res.ok) $("modal-pw-output").textContent = res.password;
    }

    ["modal-pw-len", "m-pw-upper", "m-pw-lower", "m-pw-digits", "m-pw-symbols", "m-pw-noamb"].forEach(
      (id) => $(id).addEventListener("input", refreshModalPassword)
    );
    await refreshModalPassword();
  }

  function openChangeMasterPasswordModal() {
    openModal({
      title: "🔑 修改主密码",
      bodyHtml: `
        <p style="font-size:12.5px;color:var(--text-secondary);margin-bottom:14px;line-height:1.5">
          修改主密码将重新生成随机盐值 (Salt)，并对全库所有密码、TOTP 密钥、密保答案与恢复码重新执行 AES-256-GCM 上下文绑定加密。
        </p>
        <div class="form-group">
          <label>当前主密码</label>
          <input type="password" id="mpw-old" placeholder="输入当前主密码校验身份" />
        </div>
        <div class="form-group">
          <label>新主密码</label>
          <input type="password" id="mpw-new" placeholder="输入新主密码（至少 8 位字符）" />
          <div id="mpw-pwd-meter" class="pwd-meter-wrap hidden">
            <div class="pwd-meter-track"><div id="mpw-pwd-fill" class="pwd-meter-fill"></div></div>
            <div id="mpw-pwd-hint" class="pwd-meter-hint"></div>
          </div>
        </div>
        <div class="form-group">
          <label>确认新主密码</label>
          <input type="password" id="mpw-confirm" placeholder="再次输入新主密码" />
        </div>
      `,
      footerButtons: [
        { label: "取消", className: "btn-ghost", onClick: closeModal },
        {
          label: "确认重加密并保存",
          className: "btn-primary",
          onClick: async () => {
            const oldP = $("mpw-old").value;
            const newP = $("mpw-new").value;
            const cfmP = $("mpw-confirm").value;
            if (!oldP || !newP) return showToast("请填写完整密码信息", "error");
            if (newP.length < 8) return showToast("新主密码长度至少需要 8 个字符", "error");
            if (newP !== cfmP) return showToast("两次输入的新主密码不一致", "error");
            const doRotate = async (mode = "abort") => {
              const res = await api().change_master_password(oldP, newP, mode);
              if (res.conflict) return openConflictModal(doRotate);
              if (!res.ok) return showToast(res.error || "修改失败", "error");
              closeModal();
              showToast("主密码已更新，全库敏感数据已完成重加密！", "success");
              applyUnlockedState(res, state.selectedId);
            };
            await doRotate("abort");
          },
        },
      ],
    });

    const mpwNewEl = $("mpw-new");
    if (mpwNewEl) {
      mpwNewEl.addEventListener("input", () => {
        updateStrengthMeter(mpwNewEl.value, "mpw-pwd-meter", "mpw-pwd-fill", "mpw-pwd-hint");
      });
    }
  }

  function openAutoLockModal() {
    const presets = [
      { value: 0, label: "关闭闲置自动锁定" },
      { value: 1, label: "闲置 1 分钟后自动锁定" },
      { value: 5, label: "闲置 5 分钟后自动锁定" },
      { value: 15, label: "闲置 15 分钟后自动锁定（推荐）" },
      { value: 30, label: "闲置 30 分钟后自动锁定" },
      { value: 60, label: "闲置 1 小时后自动锁定" },
      { value: 120, label: "闲置 2 小时后自动锁定" },
    ];
    const curMins = Number(state.autoLockMinutes) || 0;
    const hasPreset = presets.some((p) => p.value === curMins);
    const optionsHtml = [
      ...presets,
      ...(hasPreset ? [] : [{ value: curMins, label: `闲置 ${curMins} 分钟后自动锁定` }]),
    ]
      .map(
        (opt) =>
          `<option value="${opt.value}" ${opt.value === curMins ? "selected" : ""}>${escapeHtml(
            opt.label
          )}</option>`
      )
      .join("");

    openModal({
      title: "🔒 自动锁定安全策略",
      bodyHtml: `
        <p style="font-size:12.5px;color:var(--text-secondary);margin-bottom:14px;line-height:1.55">
          自动锁定触发时，应用会立即清除内存中的派生密钥与明文凭据，并清空编辑区输入项（包括电脑休眠唤醒超时场景）。
        </p>
        <div class="form-group">
          <label for="modal-autolock-minutes">闲置超时锁定时间</label>
          <select id="modal-autolock-minutes">${optionsHtml}</select>
        </div>
        <label class="checkbox-row" style="margin-top:12px;margin-bottom:0">
          <input type="checkbox" id="modal-lock-minimize" ${state.lockOnMinimize ? "checked" : ""} />
          <span>窗口最小化或切入后台隐藏时立即锁定密码库</span>
        </label>
      `,
      footerButtons: [
        { label: "取消", className: "btn-ghost", onClick: closeModal },
        {
          label: "保存设置",
          className: "btn-primary",
          onClick: async () => {
            const mins = parseInt($("modal-autolock-minutes").value, 10) || 0;
            const minLock = $("modal-lock-minimize").checked;
            const res = await api().set_auto_lock_prefs(mins, minLock);
            if (!res.ok) return showToast(res.error || "保存失败", "error");
            state.autoLockMinutes = res.auto_lock_minutes;
            state.lockOnMinimize = res.lock_on_minimize;
            state.lastActivityAt = Date.now();
            syncAutoLockLabel();
            closeModal();
            showToast("自动锁定策略已更新", "success");
          },
        },
      ],
    });
  }

  async function openBackupHistoryModal() {
    openModal({
      title: "🕘 分层历史快照与恢复",
      wide: true,
      bodyHtml: `<p style="font-size:13px;color:var(--text-muted)">正在读取 <code>.vault_backups</code> 历史快照列表...</p>`,
      footerButtons: [{ label: "关闭", className: "btn-ghost", onClick: closeModal }],
    });

    const res = await api().list_backups();
    if ($("modal-overlay").classList.contains("hidden")) return;

    if (!res || !res.ok) {
      openModal({
        title: "🕘 分层历史快照与恢复",
        wide: true,
        bodyHtml: `<div class="form-error">${escapeHtml((res && res.error) || "读取快照列表失败")}</div>`,
        footerButtons: [{ label: "关闭", className: "btn-ghost", onClick: closeModal }],
      });
      return;
    }

    const backups = res.backups || [];
    const listHtml =
      backups.length === 0
        ? `<div style="padding:18px;text-align:center;color:var(--text-muted);font-size:13px">当前暂无历史快照（每次修改保存时将自动生成分层备份）</div>`
        : `<div class="backup-list">${backups
            .map((b) => {
              const kb = Math.max(0.1, (Number(b.size_bytes) || 0) / 1024).toFixed(1);
              const cntText =
                typeof b.entry_count === "number" ? `${b.entry_count} 条记录 · ` : "";
              return `
                <div class="backup-item">
                  <div class="backup-item-main">
                    <div class="backup-item-time">${escapeHtml(b.created_at)}</div>
                    <div class="backup-item-sub">${cntText}${kb} KB · ${escapeHtml(b.filename)}</div>
                  </div>
                  <button type="button" class="btn btn-ghost btn-xs btn-restore-snap" data-fn="${escapeHtml(
                    b.filename
                  )}" data-time="${escapeHtml(b.created_at)}">恢复此版本</button>
                </div>
              `;
            })
            .join("")}</div>`;

    openModal({
      title: "🕘 分层历史快照与恢复",
      wide: true,
      bodyHtml: `
        <p style="font-size:12.5px;color:var(--text-secondary);line-height:1.55">
          系统采用分层保留策略（自动保留最近 10 次修改 + 24 小时每小时 + 30 天每日 + 12 周每周快照）。恢复任意历史版本前，会自动将当前文件备份一份，确保随时可逆。
        </p>
        ${listHtml}
      `,
      footerButtons: [{ label: "关闭", className: "btn-ghost", onClick: closeModal }],
    });

    document.querySelectorAll(".btn-restore-snap").forEach((btn) => {
      btn.addEventListener("click", () => {
        const fn = btn.getAttribute("data-fn");
        const snapTime = btn.getAttribute("data-time");
        openModal({
          title: "确认恢复历史快照",
          bodyHtml: `
            <p style="font-size:13px;line-height:1.65">
              确定要将当前密码库恢复至 <strong>${escapeHtml(snapTime)}</strong> 的快照版本吗？<br/>
              <span style="font-size:12px;color:var(--text-muted)">恢复前系统会先将您当前的 .md 文件自动存入 .vault_backups 快照中，不会丢失现有数据。</span>
            </p>
          `,
          footerButtons: [
            {
              label: "返回列表",
              className: "btn-ghost",
              onClick: () => openBackupHistoryModal(),
            },
            {
              label: "确认恢复",
              className: "btn-primary",
              onClick: async () => {
                const r = await api().restore_backup(fn);
                closeModal();
                if (!r || !r.ok) {
                  showToast((r && r.error) || "恢复快照失败", "error");
                  return;
                }
                if (r.requires_unlock) {
                  stopTotpTimer();
                  state.entries = [];
                  state.revealedSecrets.clear();
                  state.healthReport = null;
                  renderAuthStatus(r);
                  showToast("历史快照已恢复，该快照使用历史主密码加密，请重新输入主密码解锁", "info");
                } else {
                  showToast(`已成功恢复至 ${snapTime} 的快照版本`, "success");
                  applyUnlockedState(r);
                }
              },
            },
          ],
        });
      });
    });
  }

  function openImportExportModal() {
    openModal({
      title: "📥 批量导入与安全导出",
      wide: true,
      bodyHtml: `
        <div class="ie-section-card">
          <div class="ie-section-title">📥 从浏览器或其他密码管家导入 CSV</div>
          <p style="font-size:12.5px;color:var(--text-secondary);line-height:1.55;margin-bottom:10px">
            自动识别 <strong>Chrome / Edge / Firefox / Bitwarden / 1Password</strong> 导出的 CSV 表头，自动跳过库内重复项，并将所有密码与 TOTP 种子使用当前主密码加密后持久化至 <code>.md</code>。
          </p>
          <div class="form-group" style="margin-bottom:10px">
            <label for="ie-import-cat">默认归入分类（若 CSV 自带文件夹/分组列则优先保留原分组）</label>
            <input type="text" id="ie-import-cat" value="外部导入" placeholder="例如：外部导入 / 浏览器迁入" />
          </div>
          <button type="button" class="btn btn-primary btn-sm" id="btn-ie-do-import">选择 CSV 文件并加密导入...</button>
        </div>

        <div class="ie-section-card" style="margin-bottom:0">
          <div class="ie-section-title">📤 导出当前密码库备份</div>
          <p style="font-size:12.5px;color:var(--text-secondary);line-height:1.55;margin-bottom:10px">
            日常跨设备同步或冷备推荐导出「<strong>加密 Markdown (.md)</strong>」；如需迁移至其他软件，须再次验证主密码后方可导出「<strong>明文 CSV</strong>」（导出后请妥善粉碎明文文件）。
          </p>
          <div style="margin-bottom:12px">
            <button type="button" class="btn btn-ghost btn-sm" id="btn-ie-export-md">🔒 导出加密 Markdown 备份 (.md)</button>
          </div>
          <div class="form-group" style="margin-bottom:8px">
            <label for="ie-export-mpw">导出明文 CSV 二次身份校验（输入当前主密码）</label>
            <div class="category-select-row">
              <input type="password" id="ie-export-mpw" placeholder="输入主密码以解锁明文 CSV 导出..." autocomplete="off" />
              <button type="button" class="btn btn-danger-ghost btn-sm" id="btn-ie-export-csv">导出明文 CSV</button>
            </div>
          </div>
        </div>
      `,
      footerButtons: [{ label: "关闭", className: "btn-ghost", onClick: closeModal }],
    });

    const importBtn = $("btn-ie-do-import");
    if (importBtn) {
      importBtn.addEventListener("click", async () => {
        const defaultCat = ($("ie-import-cat").value || "外部导入").trim() || "外部导入";
        const doImport = async (mode = "abort") => {
          const res = await api().import_csv_file(defaultCat, mode);
          if (!res || res.cancelled) return;
          if (res.conflict) return openConflictModal(doImport);
          if (!res.ok) {
            showToast(res.error || "导入 CSV 失败", "error");
            return;
          }
          closeModal();
          showToast(
            `成功从 ${res.detected_source || "CSV"} 加密导入 ${res.imported_count} 条账号（跳过重复 ${res.skipped_duplicates || 0} 条）`,
            "success"
          );
          applyUnlockedState(res);
        };
        await doImport("abort");
      });
    }

    const exportMdBtn = $("btn-ie-export-md");
    if (exportMdBtn) {
      exportMdBtn.addEventListener("click", async () => {
        const res = await api().export_vault_file("encrypted_md", "");
        if (!res || res.cancelled) return;
        if (res.ok) {
          closeModal();
          showToast(`加密 Markdown 备份已导出（共 ${res.entry_count} 条记录）`, "success");
        } else {
          showToast(res.error || "导出失败", "error");
        }
      });
    }

    const exportCsvBtn = $("btn-ie-export-csv");
    if (exportCsvBtn) {
      exportCsvBtn.addEventListener("click", async () => {
        const mpw = $("ie-export-mpw").value;
        if (!mpw) {
          showToast("请先输入当前主密码进行安全验证", "error");
          $("ie-export-mpw").focus();
          return;
        }
        const res = await api().export_vault_file("plaintext_csv", mpw);
        if (!res || res.cancelled) return;
        if (res.ok) {
          $("ie-export-mpw").value = "";
          closeModal();
          showToast(
            `已导出 ${res.entry_count} 条记录至明文 CSV，使用完毕后请及时彻底删除该 CSV 文件`,
            "info"
          );
        } else {
          showToast(res.error || "验证或导出失败", "error");
        }
      });
    }
  }

  function openSwitchVaultModal() {
    openModal({
      title: "📂 切换或新建 Markdown 密码库",
      bodyHtml: `
        <p style="font-size:13px;color:var(--text-secondary);line-height:1.6;margin-bottom:12px">
          当前挂载路径：<br/>
          <code style="word-break:break-all;color:var(--text-primary)">${escapeHtml(state.vaultPath)}</code>
        </p>
        <p style="font-size:12.5px;color:var(--text-muted);line-height:1.5">
          您可以打开电脑上任意已有的 <code>.md</code> 密码库文件（例如存放在 iCloud / 坚果云 / OneDrive / Obsidian 目录中的同步文件），或指定一个新路径创建新库。
        </p>
      `,
      footerButtons: [
        { label: "取消", className: "btn-ghost", onClick: closeModal },
        {
          label: "新建 .md 库位置",
          className: "btn-ghost",
          onClick: async () => {
            const res = await api().choose_new_vault_location();
            if (res && res.ok) {
              closeModal();
              renderAuthStatus(res);
            }
          },
        },
        {
          label: "打开已有 .md 文件",
          className: "btn-primary",
          onClick: async () => {
            const res = await api().choose_existing_vault_file();
            if (res && res.ok) {
              closeModal();
              renderAuthStatus(res);
            }
          },
        },
      ],
    });
  }

  async function openUpdateModal(forceCheck = false) {
    openModal({
      title: "🔄 软件版本与自动更新",
      bodyHtml: `
        <p style="font-size:13px;color:var(--text-secondary)">
          当前本地版本：<code>v${escapeHtml(state.appVersion)}</code><br/>
          <span style="color:var(--text-muted)">正在连接 GitHub Releases 检查最新版本...</span>
        </p>
      `,
      footerButtons: [{ label: "关闭", className: "btn-ghost", onClick: closeModal }],
    });

    let info = !forceCheck && state.updateInfo && state.updateInfo.ok ? state.updateInfo : null;
    if (!info) {
      info = await api().check_app_update();
      if (info && info.ok) {
        state.updateInfo = info;
        if (typeof info.auto_check_updates === "boolean") {
          state.autoCheckUpdates = info.auto_check_updates;
        }
        renderUpdateIndicators();
      }
    }

    // Abort if modal was closed while waiting for network
    if ($("modal-overlay").classList.contains("hidden")) return;

    const autoChkHtml = `
      <label class="checkbox-row" style="margin-top:12px;margin-bottom:0">
        <input type="checkbox" id="chk-auto-update-pref" ${state.autoCheckUpdates ? "checked" : ""} />
        <span>启动软件时在后台自动检查新版本（仅向 GitHub 发起只读查询，不上传任何本地数据）</span>
      </label>
    `;

    function bindAutoUpdateToggle() {
      const chk = $("chk-auto-update-pref");
      if (chk) {
        chk.addEventListener("change", async () => {
          state.autoCheckUpdates = chk.checked;
          await api().set_auto_check_updates(chk.checked);
          showToast(
            chk.checked ? "已开启启动自动检查更新" : "已关闭启动自动检查更新",
            "info"
          );
        });
      }
    }

    if (!info || !info.ok) {
      openModal({
        title: "🔄 软件版本与自动更新",
        bodyHtml: `
          <p style="font-size:13px;line-height:1.6">
            当前本地版本：<code>v${escapeHtml(state.appVersion)}</code>
          </p>
          <div class="form-error" style="margin-top:10px">
            ${escapeHtml((info && info.error) || "检查更新失败，请检查网络连接")}
          </div>
          ${autoChkHtml}
        `,
        footerButtons: [
          { label: "关闭", className: "btn-ghost", onClick: closeModal },
          {
            label: "重试检查",
            className: "btn-ghost",
            onClick: () => openUpdateModal(true),
          },
          {
            label: "前往 GitHub Releases",
            className: "btn-primary",
            onClick: () => api().open_external_url("https://github.com/ataiben/md-vault/releases"),
          },
        ],
      });
      bindAutoUpdateToggle();
      return;
    }

    if (!info.has_update) {
      openModal({
        title: "✅ 当前已是最新版本",
        bodyHtml: `
          <p style="font-size:13.5px;line-height:1.7;color:var(--text-primary)">
            当前运行版本 <code>v${escapeHtml(info.current_version)}</code> 已是最新发布版本（远端最新：<code>${escapeHtml(info.tag_name)}</code>）。
          </p>
          ${autoChkHtml}
        `,
        footerButtons: [
          { label: "关闭", className: "btn-ghost", onClick: closeModal },
          {
            label: "重新检查",
            className: "btn-ghost",
            onClick: () => openUpdateModal(true),
          },
          {
            label: "查看历史版本",
            className: "btn-primary",
            onClick: () => api().open_external_url(info.release_url),
          },
        ],
      });
      bindAutoUpdateToggle();
      return;
    }

    const modeHint =
      info.install_mode === "git_source"
        ? "检测到当前为 Git 源码运行模式，点击下方按钮将自动执行 <code>git pull</code> 拉取最新代码并重启应用（您的本地密码库不受影响）。"
        : info.can_self_update
        ? "点击「一键下载并重启更新」将自动下载新版安装包、校验 SHA-256 完整性、替换本地程序并自动重启（您的本地 <code>.md</code> 密码库数据完全保留）。"
        : "当前运行环境请点击下方按钮前往 GitHub 下载最新安装包。";

    const notesText = info.release_notes || "包含功能体验优化与问题修复。";

    const buttons = [
      { label: "稍后再说", className: "btn-ghost", onClick: closeModal },
      {
        label: "浏览器打开下载页",
        className: "btn-ghost",
        onClick: () => api().open_external_url(info.release_url),
      },
    ];

    if (info.can_self_update) {
      buttons.push({
        label: "🚀 一键下载并重启更新",
        className: "btn-primary",
        onClick: async () => {
          const progWrap = $("update-progress-wrap");
          const progFill = $("update-progress-fill");
          const progText = $("update-progress-text");
          if (progWrap) progWrap.classList.remove("hidden");
          if (progFill) progFill.style.width = "5%";
          if (progText) progText.textContent = "正在准备下载更新...";

          document.querySelectorAll("#modal-footer button").forEach((b) => {
            b.disabled = true;
          });

          const res = await api().install_app_update();
          if (!res || !res.ok) {
            document.querySelectorAll("#modal-footer button").forEach((b) => {
              b.disabled = false;
            });
            showToast((res && res.error) || "自动更新失败，可尝试浏览器手动下载", "error");
            if (progText) {
              progText.textContent = (res && res.error) || "更新失败";
              progText.style.color = "var(--danger)";
            }
            return;
          }
          if (progFill) progFill.style.width = "100%";
          if (progText) progText.textContent = "更新已就绪，正在自动重启进入新版本...";
          showToast("更新完成，正在自动重启应用...", "success");
        },
      });
    } else {
      buttons.push({
        label: "🌐 前往下载新版",
        className: "btn-primary",
        onClick: () => api().open_external_url(info.release_url),
      });
    }

    openModal({
      title: `🎉 发现新版本 v${info.latest_version}`,
      bodyHtml: `
        <p style="font-size:13px;line-height:1.6">
          本地版本：<code>v${escapeHtml(info.current_version)}</code> &nbsp;→&nbsp;
          最新版本：<strong style="color:var(--success)">v${escapeHtml(info.latest_version)}</strong>
        </p>
        <div class="update-notes-box selectable">${escapeHtml(notesText)}</div>
        <p style="font-size:12px;color:var(--text-secondary);line-height:1.55">${modeHint}</p>
        <div id="update-progress-wrap" class="update-progress-wrap hidden">
          <div class="update-progress-bar">
            <div id="update-progress-fill" class="update-progress-fill"></div>
          </div>
          <div id="update-progress-text" class="update-progress-text">准备中...</div>
        </div>
        ${autoChkHtml}
      `,
      footerButtons: buttons,
    });
    bindAutoUpdateToggle();
  }

  // ==================== EVENT BINDINGS ====================
  function bindEvents() {
    // Show/hide password buttons on static forms
    document.querySelectorAll(".toggle-pwd-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = $(btn.getAttribute("data-target"));
        if (target) {
          target.type = target.type === "password" ? "text" : "password";
        }
      });
    });

    // Auth file chooser actions
    $("btn-auth-open-existing").addEventListener("click", async () => {
      const res = await api().choose_existing_vault_file();
      if (res && res.ok) renderAuthStatus(res);
    });

    $("btn-auth-choose-new").addEventListener("click", async () => {
      const res = await api().choose_new_vault_location();
      if (res && res.ok) renderAuthStatus(res);
    });

    $("auth-vault-path").addEventListener("click", () => api().reveal_vault_in_explorer());

    // Unlock submit
    $("unlock-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const pwd = $("unlock-password").value;
      if (!pwd) {
        $("unlock-error").textContent = "请输入主密码";
        $("unlock-error").classList.remove("hidden");
        return;
      }
      $("btn-unlock-submit").disabled = true;
      $("btn-unlock-submit").textContent = "正在验证并解密...";
      try {
        const res = await api().unlock_vault(pwd);
        if (!res.ok) {
          $("unlock-error").textContent = res.error || "解锁失败";
          $("unlock-error").classList.remove("hidden");
        } else {
          $("unlock-password").value = "";
          applyUnlockedState(res);
        }
      } finally {
        $("btn-unlock-submit").disabled = false;
        $("btn-unlock-submit").textContent = "解锁密码库";
      }
    });

    // Live strength meter on create vault master password
    if ($("create-password")) {
      $("create-password").addEventListener("input", () => {
        updateStrengthMeter(
          $("create-password").value,
          "create-pwd-meter",
          "create-pwd-fill",
          "create-pwd-hint"
        );
      });
    }

    // Create vault submit
    $("create-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const name = $("create-vault-name").value.trim() || "我的账号密码库";
      const p1 = $("create-password").value;
      const p2 = $("create-password-confirm").value;
      const useTpl = $("create-use-template").checked;

      if (p1.length < 8) {
        $("create-error").textContent = "主密码长度至少需要 8 个字符";
        $("create-error").classList.remove("hidden");
        return;
      }
      if (p1 !== p2) {
        $("create-error").textContent = "两次输入的主密码不一致";
        $("create-error").classList.remove("hidden");
        return;
      }

      $("btn-create-submit").disabled = true;
      $("btn-create-submit").textContent = "正在生成加密密钥并写入 .md...";
      try {
        const res = await api().create_vault(p1, name, useTpl);
        if (!res.ok) {
          $("create-error").textContent = res.error || "创建失败";
          $("create-error").classList.remove("hidden");
        } else {
          showToast("加密 Markdown 密码库创建成功！", "success");
          applyUnlockedState(res);
        }
      } finally {
        $("btn-create-submit").disabled = false;
        $("btn-create-submit").textContent = "创建并进入密码库";
      }
    });

    // Topbar buttons
    $("btn-reveal-md").addEventListener("click", () => api().reveal_vault_in_explorer());

    $("btn-sync-external").addEventListener("click", async () => {
      const res = await api().reload_from_disk();
      if (res.ok) {
        showToast("已从本地 .md 文件同步最新内容", "success");
        applyUnlockedState(res, state.selectedId);
      } else {
        showToast(res.error || "同步失败", "error");
      }
    });

    $("btn-new-entry").addEventListener("click", () => openEditor(null));
    $("btn-empty-new").addEventListener("click", () => openEditor(null));
    $("btn-open-pwgen").addEventListener("click", openStandalonePasswordModal);

    if ($("btn-sidebar-settings")) {
      $("btn-sidebar-settings").addEventListener("click", (ev) => {
        ev.stopPropagation();
        const pop = $("settings-popover");
        if (!pop) return;
        const willShow = pop.classList.contains("hidden");
        pop.classList.toggle("hidden", !willShow);
        $("btn-sidebar-settings").classList.toggle("active", willShow);
      });
    }

    document.addEventListener("click", (ev) => {
      const wrap = $("sidebar-settings-wrap");
      if (wrap && !wrap.contains(ev.target)) {
        closeSettingsPopover();
      }
    });

    $("btn-switch-vault").addEventListener("click", () => {
      closeSettingsPopover();
      openSwitchVaultModal();
    });
    if ($("btn-import-export")) {
      $("btn-import-export").addEventListener("click", () => {
        closeSettingsPopover();
        openImportExportModal();
      });
    }
    if ($("btn-backup-history")) {
      $("btn-backup-history").addEventListener("click", () => {
        closeSettingsPopover();
        openBackupHistoryModal();
      });
    }
    if ($("btn-auto-lock")) {
      $("btn-auto-lock").addEventListener("click", () => {
        closeSettingsPopover();
        openAutoLockModal();
      });
    }
    $("btn-change-mpw").addEventListener("click", () => {
      closeSettingsPopover();
      openChangeMasterPasswordModal();
    });

    $("btn-toggle-theme").addEventListener("click", () => {
      const html = document.documentElement;
      const next = html.getAttribute("data-theme") === "dark" ? "light" : "dark";
      html.setAttribute("data-theme", next);
      localStorage.setItem("md_vault_theme", next);
      syncThemeLabel();
    });

    if ($("btn-check-update")) {
      $("btn-check-update").addEventListener("click", () => {
        closeSettingsPopover();
        openUpdateModal(false);
      });
    }
    if ($("btn-auth-update")) {
      $("btn-auth-update").addEventListener("click", () => openUpdateModal(false));
    }

    $("btn-lock-vault").addEventListener("click", async () => {
      await lockWorkspaceWithReason("密码库已安全锁定");
    });

    // Left Sidebar Quick Filters
    document.querySelectorAll("#quick-nav-list .nav-item").forEach((li) => {
      li.addEventListener("click", () => {
        state.filterType = li.getAttribute("data-filter-type");
        state.filterCategory = "";
        state.filterTag = "";
        if (state.mode === "edit") state.mode = "view";
        state.revealedSecrets.clear();
        stopTotpTimer();
        const filtered = getFilteredEntries();
        if (!filtered.some((e) => e.id === state.selectedId)) {
          state.selectedId = filtered.length ? filtered[0].id : null;
        }
        renderWorkspace();
      });
    });

    $("btn-add-category").addEventListener("click", () => openAddCategoryModal());
    $("btn-clear-tag").addEventListener("click", () => {
      state.filterTag = "";
      renderWorkspace();
    });

    // Search Bar
    $("search-input").addEventListener("input", (ev) => {
      state.searchQuery = ev.target.value;
      $("btn-clear-search").classList.toggle("hidden", !state.searchQuery);
      renderAccountList();
    });

    $("btn-clear-search").addEventListener("click", () => {
      state.searchQuery = "";
      $("search-input").value = "";
      $("btn-clear-search").classList.add("hidden");
      renderAccountList();
    });

    // Editor Form Controls
    $("btn-inline-new-cat").addEventListener("click", () => {
      openAddCategoryModal((createdCat) => {
        populateCategorySelect(createdCat);
        renderPresetTagsBar();
      });
    });

    $("field-category").addEventListener("change", () => {
      renderPresetTagsBar();
    });

    $("field-tags").addEventListener("input", syncPresetTagHighlights);

    $("field-tags").addEventListener("keydown", async (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        const currentCat = ($("field-category").value || "未分类").trim();
        const tags = parseTagsInput();
        if (tags.length === 0) return;
        const doSaveQuickTags = async (mode = "abort") => {
          let lastRes = null;
          for (const t of tags) {
            lastRes = await api().add_saved_tag(currentCat, t, mode);
            if (lastRes && lastRes.conflict) {
              return openConflictModal(doSaveQuickTags);
            }
          }
          if (lastRes && lastRes.ok) {
            state.savedTags = lastRes.saved_tags || {};
            renderPresetTagsBar();
            showToast("已将输入标签保存至当前分类快捷标签", "success");
          }
        };
        await doSaveQuickTags("abort");
      }
    });

    // Inline password generator in editor
    async function fillInlineGeneratedPassword() {
      const len = parseInt($("inline-pw-len").value, 10);
      $("inline-pw-len-val").textContent = len;
      const res = await api().generate_random_password({
        length: len,
        use_upper: $("inline-pw-upper").checked,
        use_lower: $("inline-pw-lower").checked,
        use_digits: $("inline-pw-digits").checked,
        use_symbols: $("inline-pw-symbols").checked,
        exclude_ambiguous: $("inline-pw-noamb").checked,
      });
      if (res.ok) {
        $("field-password").value = res.password;
        $("field-password").type = "text";
      }
    }

    $("btn-inline-gen-pwd").addEventListener("click", async () => {
      const box = $("inline-pwgen-box");
      box.classList.toggle("hidden");
      if (!box.classList.contains("hidden")) {
        await fillInlineGeneratedPassword();
      }
    });

    $("inline-pw-len").addEventListener("input", () => {
      $("inline-pw-len-val").textContent = $("inline-pw-len").value;
    });
    $("btn-inline-pw-refresh").addEventListener("click", fillInlineGeneratedPassword);

    if ($("field-2fa")) {
      $("field-2fa").addEventListener("input", () => updateEditorTotpPreview());
    }

    // Security QA helpers
    $("btn-add-qa-row").addEventListener("click", () => addQaRow("", ""));
    $("btn-fill-apple-qa").addEventListener("click", () => {
      const container = $("qa-rows-container");
      if (container.children.length === 0) {
        addQaRow("你少年时代最好的朋友叫什么名字？", "");
        addQaRow("你的第一份工作是在哪个城市？", "");
        addQaRow("你理想的工作是什么？", "");
      } else {
        showToast("当前已有密保问题行，可直接修改或点击 + 添加", "info");
      }
    });

    $("btn-cancel-edit").addEventListener("click", () => {
      state.mode = "view";
      renderRightPane();
    });

    $("entry-editor").addEventListener("submit", submitEditorForm);

    // Modal close
    $("btn-modal-close").addEventListener("click", closeModal);
    $("modal-overlay").addEventListener("click", (ev) => {
      if (ev.target === $("modal-overlay")) closeModal();
    });

    // Global Keyboard Shortcuts
    document.addEventListener("keydown", (ev) => {
      const isAppVisible = !$("app-workspace").classList.contains("hidden");
      if (ev.key === "Escape") {
        if (!$("modal-overlay").classList.contains("hidden")) {
          closeModal();
          return;
        }
        if ($("settings-popover") && !$("settings-popover").classList.contains("hidden")) {
          closeSettingsPopover();
          return;
        }
      }
      if (!isAppVisible) return;

      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "f") {
        ev.preventDefault();
        $("search-input").focus();
        $("search-input").select();
      } else if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "n") {
        ev.preventDefault();
        openEditor(null);
      } else if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "l") {
        ev.preventDefault();
        $("btn-lock-vault").click();
      } else if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "s" && state.mode === "edit") {
        ev.preventDefault();
        $("entry-editor").requestSubmit();
      }
    });

    // Idle & Minimize Auto-Lock Activity Tracking
    ["mousemove", "mousedown", "keydown", "wheel", "touchstart"].forEach((evtName) => {
      document.addEventListener(evtName, touchActivity, { passive: true });
    });

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        if (state.lockOnMinimize && isWorkspaceUnlocked()) {
          lockWorkspaceWithReason("窗口隐藏或最小化，密码库已自动安全锁定");
        }
      } else {
        checkIdleAutoLock();
      }
    });

    window.addEventListener("focus", () => {
      checkIdleAutoLock();
    });

    setInterval(checkIdleAutoLock, 5000);
  }

  // Backend auto-lock hook (e.g. native OS window minimized event)
  window.onBackendAutoLocked = async function (reason) {
    if (state.lockingInProgress) return;
    stopTotpTimer();
    closeModal();
    closeSettingsPopover();
    clearSensitiveDomInputs();
    state.entries = [];
    state.revealedSecrets.clear();
    state.healthReport = null;
    state.mode = "view";
    try {
      const status = await api().get_status();
      renderAuthStatus(status);
    } catch (_) {
      $("auth-screen").classList.remove("hidden");
      $("app-workspace").classList.add("hidden");
    }
    if (reason) showToast(reason, "info");
  };

  // External file modification hook invoked from Python FileWatcher
  window.onExternalVaultChanged = function () {
    const syncBtn = $("btn-sync-external");
    if (syncBtn) syncBtn.classList.remove("hidden");
    showToast("检测到外部编辑器更新了 .md 文件，可点击顶部黄色按钮同步", "info");
  };

  // Live download progress hook invoked from Python Auto-Updater
  window.onUpdateProgress = function (payload) {
    if (!payload) return;
    const fill = $("update-progress-fill");
    const txt = $("update-progress-text");
    if (fill && typeof payload.percent === "number") {
      fill.style.width = `${Math.max(0, Math.min(100, payload.percent))}%`;
    }
    if (txt && payload.message) {
      txt.textContent = payload.message;
    }
  };

  // Restore theme & adapt macOS shortcut hints & boot
  const savedTheme = localStorage.getItem("md_vault_theme");
  if (savedTheme === "light" || savedTheme === "dark") {
    document.documentElement.setAttribute("data-theme", savedTheme);
  }
  syncThemeLabel();

  const isMac = /Mac|iPhone|iPad|iPod/i.test(navigator.platform || navigator.userAgent || "");
  if (isMac) {
    if ($("btn-new-entry")) $("btn-new-entry").title = "快捷键 ⌘N";
    if ($("btn-lock-vault")) $("btn-lock-vault").title = "立即锁定密码库 (⌘L)";
    if ($("search-input")) {
      $("search-input").placeholder = "搜索标题、账号、平台、标签、手机、备注... (⌘F)";
    }
  }

  bindEvents();

  if (window.pywebview && window.pywebview.api) {
    refreshBootStatus();
  } else {
    window.addEventListener("pywebviewready", refreshBootStatus);
  }
})();
