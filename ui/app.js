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
    filterType: "all", // "all" | "favorite" | "category"
    filterCategory: "",
    filterTag: "",
    searchQuery: "",
    selectedId: null,
    mode: "view", // "view" | "edit"
    revealedFields: new Set(),
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
  function openModal({ title, bodyHtml, footerButtons = [] }) {
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
    $("modal-body").innerHTML = "";
    $("modal-footer").innerHTML = "";
  }

  // ==================== BOOT & AUTH ====================
  async function refreshBootStatus() {
    try {
      const status = await api().get_status();
      renderAuthStatus(status);
    } catch (err) {
      showToast("初始化状态读取失败: " + err.message, "error");
    }
  }

  function renderAuthStatus(status) {
    state.vaultPath = status.vault_path || "";
    state.vaultName = status.vault_name || "我的账号密码库";
    $("auth-vault-path").textContent = state.vaultPath;

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
      setTimeout(() => $("create-password").focus(), 60);
    }
  }

  function applyUnlockedState(res, preferredId = null) {
    state.vaultName = res.vault_name || "我的账号密码库";
    state.vaultPath = res.vault_path || "";
    state.categories = res.categories || [];
    state.entries = res.entries || [];
    state.tagCounts = res.tag_counts || {};
    state.savedTags = res.saved_tags || {};

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
      showToast("已识别外部编辑器填写的明文密码，并自动使用主密码加密落盘", "success");
    }

    if (preferredId && state.entries.some((e) => e.id === preferredId)) {
      state.selectedId = preferredId;
    } else if (!state.selectedId || !state.entries.some((e) => e.id === state.selectedId)) {
      const visible = getFilteredEntries();
      state.selectedId = visible.length > 0 ? visible[0].id : null;
    }

    state.mode = "view";
    state.revealedFields.clear();
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

  function renderSidebar() {
    $("count-all").textContent = state.entries.length;
    $("count-fav").textContent = state.entries.filter((e) => e.favorite).length;

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
        if (state.mode === "view") state.revealedFields.clear();
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
      if (tagsTitleEl) tagsTitleEl.textContent = "地区 / 用途标签";
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
      card.className = `account-card${entry.id === state.selectedId ? " active" : ""}`;
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
        state.selectedId = entry.id;
        state.mode = "view";
        state.revealedFields.clear();
        renderAccountList();
        renderRightPane();
      });
      listEl.appendChild(card);
    });
  }

  function renderRightPane() {
    const emptyEl = $("detail-empty");
    const viewEl = $("detail-view");
    const editorEl = $("entry-editor");

    if (state.mode === "edit") {
      emptyEl.classList.add("hidden");
      viewEl.classList.add("hidden");
      editorEl.classList.remove("hidden");
      return;
    }

    editorEl.classList.add("hidden");
    const entry = state.entries.find((e) => e.id === state.selectedId);
    if (!entry) {
      emptyEl.classList.remove("hidden");
      viewEl.classList.add("hidden");
      return;
    }

    emptyEl.classList.add("hidden");
    viewEl.classList.remove("hidden");

    const isPwdShown = state.revealedFields.has("pwd");
    const is2faShown = state.revealedFields.has("2fa");

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

    const hasSecurity =
      (entry.security_questions && entry.security_questions.length > 0) ||
      Boolean(entry.two_fa_recovery);

    let securityPanelHtml = "";
    if (hasSecurity) {
      const qaHtml = (entry.security_questions || [])
        .map((qa, idx) => {
          const key = `qa_${idx}`;
          const shown = state.revealedFields.has(key);
          return `
            <div class="field-row">
              <div class="field-meta">
                <div class="field-label">密保问题 ${idx + 1}：${escapeHtml(qa.question)}</div>
                <div class="field-value mono selectable">${
                  qa.answer ? (shown ? escapeHtml(qa.answer) : "••••••••••••") : "<span style='color:var(--text-muted)'>未填写答案</span>"
                }</div>
              </div>
              ${
                qa.answer
                  ? `<div class="field-ops">
                      <button type="button" class="btn btn-ghost btn-xs reveal-trigger" data-reveal-key="${key}">${shown ? "隐藏" : "显示"}</button>
                      <button type="button" class="btn btn-ghost btn-xs copy-trigger" data-copy="${escapeHtml(qa.answer)}" data-secret="1">复制答案</button>
                    </div>`
                  : ""
              }
            </div>
          `;
        })
        .join("");

      const twoFaHtml = entry.two_fa_recovery
        ? `
          <div class="field-row">
            <div class="field-meta">
              <div class="field-label">2FA 密钥 / 备用恢复码（AES-256-GCM 加密存储）</div>
              <div class="field-value mono selectable" style="white-space:pre-wrap">${
                is2faShown ? escapeHtml(entry.two_fa_recovery) : "••••-••••-••••-••••"
              }</div>
            </div>
            <div class="field-ops">
              <button type="button" class="btn btn-ghost btn-xs reveal-trigger" data-reveal-key="2fa">${is2faShown ? "隐藏" : "显示"}</button>
              <button type="button" class="btn btn-ghost btn-xs copy-trigger" data-copy="${escapeHtml(entry.two_fa_recovery)}" data-secret="1">复制恢复码</button>
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
            <div class="field-label">登录密码（落盘状态：已通过 AES-256-GCM 加密）</div>
            <div class="field-value mono selectable">${
              entry.password
                ? isPwdShown
                  ? escapeHtml(entry.password)
                  : "••••••••••••••••"
                : "<span style='color:var(--text-muted)'>未设置密码</span>"
            }</div>
          </div>
          ${
            entry.password
              ? `<div class="field-ops">
                  <button type="button" class="btn btn-ghost btn-xs reveal-trigger" data-reveal-key="pwd">${isPwdShown ? "隐藏" : "显示"}</button>
                  <button type="button" class="btn btn-primary btn-xs copy-trigger" data-copy="${escapeHtml(entry.password)}" data-secret="1">复制密码</button>
                </div>`
              : ""
          }
        </div>
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

    // Bind detail button actions
    $("btn-detail-fav").addEventListener("click", async () => {
      const res = await api().toggle_favorite(entry.id);
      if (res.ok) applyUnlockedState(res, entry.id);
    });

    $("btn-detail-duplicate").addEventListener("click", () => {
      openEditor(entry, true);
      showToast("已复制当前账号内容，修改差异项后点击保存即可创建", "info");
    });
    $("btn-detail-edit").addEventListener("click", () => openEditor(entry, false));
    $("btn-detail-delete").addEventListener("click", () => confirmDeleteEntry(entry));

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
      btn.addEventListener("click", () => {
        const key = btn.getAttribute("data-reveal-key");
        if (state.revealedFields.has(key)) state.revealedFields.delete(key);
        else state.revealedFields.add(key);
        renderRightPane();
      });
    });

    viewEl.querySelectorAll(".copy-trigger").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const val = btn.getAttribute("data-copy");
        const isSecret = btn.getAttribute("data-secret") === "1";
        const res = await api().copy_to_clipboard(val, isSecret ? 30 : 0);
        if (res.ok) {
          showToast(
            isSecret ? "敏感信息已复制（30 秒后将自动清空剪贴板）" : "已复制到剪贴板",
            "success"
          );
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
    const cats = state.categories.length ? [...state.categories] : ["苹果商店与生态", "邮箱账号", "未分类"];
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
        const res = await api().delete_saved_tag(currentCat, tag);
        if (res.ok) {
          state.savedTags = res.saved_tags || {};
          renderPresetTagsBar();
          showToast(`已删除快捷标签「${tag}」`, "info");
        } else {
          showToast(res.error || "删除标签失败", "error");
        }
      });

      chip.appendChild(labelBtn);
      chip.appendChild(delBtn);
      bar.appendChild(chip);
    });
  }

  function openEditor(entry = null, isDuplicate = false) {
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
      : state.categories[0] || "苹果商店与生态";

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
    $("field-2fa").value = hasSource ? entry.two_fa_recovery || "" : "";
    $("field-notes").value = hasSource ? entry.notes || "" : "";
    $("inline-pwgen-box").classList.add("hidden");

    const qaContainer = $("qa-rows-container");
    qaContainer.innerHTML = "";
    if (hasSource && entry.security_questions && entry.security_questions.length > 0) {
      entry.security_questions.forEach((qa) => addQaRow(qa.question, qa.answer));
    }

    renderPresetTagsBar();
    renderRightPane();
    setTimeout(() => {
      $("field-title").focus();
      if (isDuplicate) $("field-title").select();
    }, 40);
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
      phone: $("field-phone").value.trim(),
      recovery_email: $("field-recovery-email").value.trim(),
      url: $("field-url").value.trim(),
      security_questions: qaRows,
      two_fa_recovery: $("field-2fa").value.trim(),
      notes: $("field-notes").value,
      custom_fields: state.editingCustomFields,
    };

    const res = await api().save_entry(payload);
    if (!res.ok) {
      showToast(res.error || "保存失败", "error");
      return;
    }
    showToast("已加密保存并更新至本地 .md 文件", "success");
    applyUnlockedState(res, res.saved_id);
  }

  function confirmDeleteEntry(entry) {
    openModal({
      title: "确认删除账号",
      bodyHtml: `<p style="line-height:1.6">确定要从本地 Markdown 密码库中删除 <strong>${escapeHtml(
        entry.title
      )}</strong> 吗？<br/><span style="font-size:12px;color:var(--text-muted)">删除前系统会自动在 .vault_backups 目录保留历史快照。</span></p>`,
      footerButtons: [
        { label: "取消", className: "btn-ghost", onClick: closeModal },
        {
          label: "确认删除",
          className: "btn-danger",
          onClick: async () => {
            const res = await api().delete_entry(entry.id);
            closeModal();
            if (res.ok) {
              showToast("账号记录已删除", "info");
              state.selectedId = null;
              applyUnlockedState(res);
            } else {
              showToast(res.error || "删除失败", "error");
            }
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
            const res = await api().add_category(name);
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
            const res = await api().rename_category(oldName, newName);
            if (!res.ok) return showToast(res.error, "error");
            closeModal();
            if (state.filterType === "category" && state.filterCategory === oldName) {
              state.filterCategory = newName;
            }
            showToast("分类已重命名", "success");
            applyUnlockedState(res, state.selectedId);
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
            const res = await api().delete_category(catName, "未分类");
            closeModal();
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
            await api().copy_to_clipboard(val, 30);
            showToast("强密码已复制（30 秒后自动清空剪贴板）", "success");
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
          修改主密码将重新生成随机盐值 (Salt)，并对全库所有密码、密保答案与恢复码重新执行 AES-256-GCM 加密。
        </p>
        <div class="form-group">
          <label>当前主密码</label>
          <input type="password" id="mpw-old" placeholder="输入当前主密码校验身份" />
        </div>
        <div class="form-group">
          <label>新主密码</label>
          <input type="password" id="mpw-new" placeholder="输入新主密码（至少 4 位）" />
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
            if (newP !== cfmP) return showToast("两次输入的新主密码不一致", "error");
            const res = await api().change_master_password(oldP, newP);
            if (!res.ok) return showToast(res.error || "修改失败", "error");
            closeModal();
            showToast("主密码已更新，全库敏感数据已完成重加密！", "success");
            applyUnlockedState(res, state.selectedId);
          },
        },
      ],
    });
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

    // Create vault submit
    $("create-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const name = $("create-vault-name").value.trim() || "我的账号密码库";
      const p1 = $("create-password").value;
      const p2 = $("create-password-confirm").value;
      const useTpl = $("create-use-template").checked;

      if (p1.length < 4) {
        $("create-error").textContent = "主密码长度至少需要 4 位字符";
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
    $("btn-switch-vault").addEventListener("click", openSwitchVaultModal);
    $("btn-change-mpw").addEventListener("click", openChangeMasterPasswordModal);

    $("btn-toggle-theme").addEventListener("click", () => {
      const html = document.documentElement;
      const next = html.getAttribute("data-theme") === "dark" ? "light" : "dark";
      html.setAttribute("data-theme", next);
      localStorage.setItem("md_vault_theme", next);
    });

    $("btn-lock-vault").addEventListener("click", async () => {
      const status = await api().lock_vault();
      state.entries = [];
      state.revealedFields.clear();
      renderAuthStatus(status);
      showToast("密码库已安全锁定", "info");
    });

    // Left Sidebar Quick Filters
    document.querySelectorAll("#quick-nav-list .nav-item").forEach((li) => {
      li.addEventListener("click", () => {
        state.filterType = li.getAttribute("data-filter-type");
        state.filterCategory = "";
        state.filterTag = "";
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
        let lastRes = null;
        for (const t of tags) {
          lastRes = await api().add_saved_tag(currentCat, t);
        }
        if (lastRes && lastRes.ok) {
          state.savedTags = lastRes.saved_tags || {};
          renderPresetTagsBar();
          showToast("已将输入标签保存至当前分类快捷标签", "success");
        }
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
      if (ev.key === "Escape" && !$("modal-overlay").classList.contains("hidden")) {
        closeModal();
        return;
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
  }

  // External file modification hook invoked from Python FileWatcher
  window.onExternalVaultChanged = function () {
    const syncBtn = $("btn-sync-external");
    if (syncBtn) syncBtn.classList.remove("hidden");
    showToast("检测到外部编辑器更新了 .md 文件，可点击顶部黄色按钮同步", "info");
  };

  // Restore theme & adapt macOS shortcut hints & boot
  const savedTheme = localStorage.getItem("md_vault_theme");
  if (savedTheme === "light" || savedTheme === "dark") {
    document.documentElement.setAttribute("data-theme", savedTheme);
  }

  const isMac = /Mac|iPhone|iPad|iPod/i.test(navigator.platform || navigator.userAgent || "");
  if (isMac) {
    if ($("btn-new-entry")) $("btn-new-entry").title = "快捷键 ⌘N";
    if ($("btn-lock-vault")) $("btn-lock-vault").title = "立即锁定密码库 (⌘L)";
    if ($("search-input")) {
      $("search-input").placeholder = "搜索标题、账号、美区/土区、手机、备注... (⌘F)";
    }
  }

  bindEvents();

  if (window.pywebview && window.pywebview.api) {
    refreshBootStatus();
  } else {
    window.addEventListener("pywebviewready", refreshBootStatus);
  }
})();
