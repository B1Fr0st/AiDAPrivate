from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None


def fail(message: str) -> None:
    raise SystemExit(f"AiDA Camoufox reverse MCP multipage patch failed: {message}")


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except FileNotFoundError:
        fail(f"missing {path}")


def write_text(path: pathlib.Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        fail(f"missing anchor {label}")
    return text.replace(old, new, 1)


def patch_navigation_capture(path: pathlib.Path, text: str) -> str:
    if "capture_from_start: bool = False" not in text:
        with_page = (
            "async def navigate(\n"
            "    url: str,\n"
            "    page_id: str | None = None,\n"
            "    wait_until: str = \"load\",\n"
        )
        without_page = (
            "async def navigate(\n"
            "    url: str,\n"
            "    wait_until: str = \"load\",\n"
        )
        replacement = (
            "async def navigate(\n"
            "    url: str,\n"
            "    page_id: str | None = None,\n"
            "    capture_from_start: bool = False,\n"
            "    capture_body: bool = False,\n"
            "    capture_url_pattern: str = \"**/*\",\n"
            "    wait_until: str = \"load\",\n"
        )
        if with_page in text:
            text = text.replace(with_page, replacement, 1)
        elif without_page in text:
            text = text.replace(without_page, replacement, 1)
        else:
            fail(f"navigation capture signature anchor missing {path}")
    if "capture_from_start_enabled" not in text:
        text = replace_once(
            text,
            "        warnings: list[str] = []\n        hooks_injected: list[str] = []\n",
            "        warnings: list[str] = []\n        hooks_injected: list[str] = []\n\n"
            "        if capture_from_start:\n"
            "            browser_manager._capturing = True\n"
            "            browser_manager._capture_pattern = capture_url_pattern or \"**/*\"\n"
            "            browser_manager._capture_body = capture_body\n"
            "            warnings.append(\"capture_from_start_enabled\")\n",
            "navigation capture start",
        )
    if "capture_from_start: bool = False" not in text or "capture_from_start_enabled" not in text:
        fail(f"navigation capture validation failed {path}")
    return text


def patch_browser(path: pathlib.Path) -> None:
    text = read_text(path)
    if "self._aida_multipage_patch = 4" in text:
        updated = text
        updated = updated.replace(
            "        page.on(\"close\", lambda pid=page_id: self._on_page_closed(pid))\n",
            "        page.on(\"close\", lambda *_, pid=page_id: self._on_page_closed(pid))\n",
        )
        updated = updated.replace(
            "            page.on(\"crash\", lambda pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid))\n",
            "            page.on(\"crash\", lambda *_, pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid))\n",
        )
        updated = updated.replace(
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        page = await ctx.new_page()\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        try:\n"
            "            page = await ctx.new_page()\n"
            "        except Exception:\n"
            "            self._discard_pending_page_id(requested_context_id, page_id)\n"
            "            raise\n"
            "        privacy_info = await _verify_private_page(page)\n"
            "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
            "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
            "        if not privacy_info.get(\"webrtc_disabled\"):\n"
            "            with contextlib.suppress(Exception):\n"
            "                await page.close()\n"
            "            raise RuntimeError(\"Camoufox privacy verification failed: WebRTC is still exposed\")\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
        )
        if "page_privacy_verified" not in updated:
            updated = replace_once(
                updated,
                "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n",
                "        privacy_info = await _verify_private_page(page)\n"
                "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
                "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
                "        if not privacy_info.get(\"webrtc_disabled\"):\n"
                "            with contextlib.suppress(Exception):\n"
                "                await page.close()\n"
                "            raise RuntimeError(\"Camoufox privacy verification failed: WebRTC is still exposed\")\n"
                "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n",
                "browser v4 page privacy guard",
            )
        if updated != text:
            write_text(path, updated)
        return
    if "self._aida_multipage_patch = 3" in text:
        updated = text.replace("        self._aida_multipage_patch = 3\n", "        self._aida_multipage_patch = 4\n")
        updated = updated.replace(
            "        page.on(\"close\", lambda pid=page_id: self._on_page_closed(pid))\n",
            "        page.on(\"close\", lambda *_, pid=page_id: self._on_page_closed(pid))\n",
        )
        updated = updated.replace(
            "            page.on(\"crash\", lambda pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid))\n",
            "            page.on(\"crash\", lambda *_, pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid))\n",
        )
        updated = updated.replace(
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        page = await ctx.new_page()\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        try:\n"
            "            page = await ctx.new_page()\n"
            "        except Exception:\n"
            "            self._discard_pending_page_id(requested_context_id, page_id)\n"
            "            raise\n"
            "        privacy_info = await _verify_private_page(page)\n"
            "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
            "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
            "        if not privacy_info.get(\"webrtc_disabled\"):\n"
            "            with contextlib.suppress(Exception):\n"
            "                await page.close()\n"
            "            raise RuntimeError(\"Camoufox privacy verification failed: WebRTC is still exposed\")\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
        )
        if "page_privacy_verified" not in updated:
            updated = replace_once(
                updated,
                "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n",
                "        privacy_info = await _verify_private_page(page)\n"
                "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
                "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
                "        if not privacy_info.get(\"webrtc_disabled\"):\n"
                "            with contextlib.suppress(Exception):\n"
                "                await page.close()\n"
                "            raise RuntimeError(\"Camoufox privacy verification failed: WebRTC is still exposed\")\n"
                "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n",
                "browser v3 page privacy guard",
            )
        if updated != text:
            write_text(path, updated)
        return
    if "self._aida_multipage_patch = 2" in text:
        updated = text.replace("        self._aida_multipage_patch = 2\n", "        self._aida_multipage_patch = 4\n")
        if "self._pending_page_ids_by_context" not in updated:
            updated = replace_once(
                updated,
                "        self._listener_page_ids: set[str] = set()\n",
                "        self._listener_page_ids: set[str] = set()\n"
                "        self._pending_page_ids_by_context: dict[str, list[str]] = {}\n",
                "browser pending page id state",
            )
        if "def _queue_pending_page_id" not in updated:
            updated = replace_once(
                updated,
                "    def _context_id_for_page(self, page: Page | None) -> str:\n",
                "    def _queue_pending_page_id(self, context_id: str, page_id: str | None) -> None:\n"
                "        pid = self._slug(page_id) if page_id else \"\"\n"
                "        if pid:\n"
                "            self._pending_page_ids_by_context.setdefault(context_id or \"default\", []).append(pid)\n\n"
                "    def _pop_pending_page_id(self, context_id: str) -> str | None:\n"
                "        queue = self._pending_page_ids_by_context.get(context_id or \"default\")\n"
                "        if not queue:\n"
                "            return None\n"
                "        pid = queue.pop(0)\n"
                "        if not queue:\n"
                "            self._pending_page_ids_by_context.pop(context_id or \"default\", None)\n"
                "        return pid\n\n"
                "    def _discard_pending_page_id(self, context_id: str, page_id: str | None) -> None:\n"
                "        pid = self._slug(page_id) if page_id else \"\"\n"
                "        queue = self._pending_page_ids_by_context.get(context_id or \"default\")\n"
                "        if pid and queue and pid in queue:\n"
                "            queue.remove(pid)\n"
                "            if not queue:\n"
                "                self._pending_page_ids_by_context.pop(context_id or \"default\", None)\n\n"
                "    def _context_id_for_page(self, page: Page | None) -> str:\n",
                "browser pending page id helpers",
            )
        updated = updated.replace(
            "            ctx.on(\"page\", lambda page, cid=context_id: self._register_page(page, None, True, \"context_page\", cid))\n",
            "            ctx.on(\"page\", lambda page, cid=context_id: self._register_page(page, self._pop_pending_page_id(cid), True, \"context_page\", cid))\n",
        )
        updated = updated.replace(
            "        ctx = self.contexts.get(context_id or \"default\") or await self.get_active_context()\n"
            "        page = await ctx.new_page()\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", context_id or self._context_id_for_page(page))\n",
            "        requested_context_id = context_id or \"default\"\n"
            "        ctx = self.contexts.get(requested_context_id) or await self.get_active_context()\n"
            "        requested_context_id = context_id or self.context_ids.get(id(ctx), \"default\")\n"
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        try:\n"
            "            page = await ctx.new_page()\n"
            "        except Exception:\n"
            "            self._discard_pending_page_id(requested_context_id, page_id)\n"
            "            raise\n"
            "        privacy_info = await _verify_private_page(page)\n"
            "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
            "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
            "        if not privacy_info.get(\"webrtc_disabled\"):\n"
            "            with contextlib.suppress(Exception):\n"
            "                await page.close()\n"
            "            raise RuntimeError(\"Camoufox privacy verification failed: WebRTC is still exposed\")\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
        )
        if "self._pending_page_ids_by_context" not in updated or "self._pop_pending_page_id(cid)" not in updated or "page_privacy_verified" not in updated:
            fail("browser v2 upgrade missing pending page id support")
        write_text(path, updated)
        return
    text = replace_once(
        text,
        "        self.pages: dict[str, Page] = {}\n"
        "        self.active_page_name: str | None = None\n"
        "        self._cm = None  # AsyncCamoufox context manager\n",
        "        self.pages: dict[str, Page] = {}\n"
        "        self.page_meta: dict[str, dict[str, Any]] = {}\n"
        "        self.context_ids: dict[int, str] = {}\n"
        "        self._page_guid_to_id: dict[str, str] = {}\n"
        "        self._listener_page_ids: set[str] = set()\n"
        "        self._pending_page_ids_by_context: dict[str, list[str]] = {}\n"
        "        self._page_counter = 0\n"
        "        self.active_page_name: str | None = None\n"
        "        self.active_page_id: str | None = None\n"
        "        self.session_id: str = _os.environ.get(\"AIDA_CAMOUFOX_SESSION_ID\", \"default\") or \"default\"\n"
        "        self._aida_multipage_patch = 4\n"
        "        self._cm = None  # AsyncCamoufox context manager\n",
        "browser init multipage state",
    )
    text = replace_once(
        text,
        "        self._nav_responses: list[dict] = []",
        "        self._nav_responses: list[dict] = []\n"
        "        self._nav_responses_by_page: dict[str, list[dict]] = {}",
        "browser nav response state",
    )
    text = replace_once(
        text,
        "            pages_info = {}\n"
        "            for name, p in self.pages.items():\n"
        "                try:\n"
        "                    pages_info[name] = p.url\n"
        "                except Exception:\n"
        "                    pages_info[name] = \"unknown\"\n"
        "            active_page = self.pages.get(self.active_page_name or \"\")\n"
        "            active_bounds = await self._page_bounds_limited(active_page) if active_page else {}\n",
        "            pages_info = await self.list_pages()\n"
        "            active_page = await self.resolve_page(None)\n"
        "            active_bounds = await self._page_bounds_limited(active_page) if active_page else {}\n",
        "browser already running page summaries",
    )
    text = replace_once(
        text,
        "                \"active_page\": self.active_page_name,\n"
        "                \"pages\": pages_info,\n",
        "                \"session_id\": self.session_id,\n"
        "                \"active_page\": self.active_page_id or self.active_page_name,\n"
        "                \"active_page_id\": self.active_page_id or self.active_page_name,\n"
        "                \"page_count\": len(self.pages),\n"
        "                \"pages\": pages_info,\n",
        "browser already running result fields",
    )
    text = replace_once(
        text,
        "            self.contexts[\"default\"] = ctx\n\n"
        "            if os_type != host_os:",
        "            self.contexts[\"default\"] = ctx\n"
        "            self._register_context(\"default\", ctx)\n\n"
        "            if os_type != host_os:",
        "browser launch context register",
    )
    text = replace_once(
        text,
        "            self._attach_listeners(page)\n"
        "            self.pages[\"default\"] = page\n"
        "            self.active_page_name = \"default\"\n",
        "            for existing_page in list(ctx.pages):\n"
        "                self._register_page(existing_page, \"default\" if existing_page is page else None, existing_page is page, \"launch_existing\")\n"
        "            page_id = self._register_page(page, \"default\", True, \"launch\")\n"
        "            page = self.pages[page_id]\n",
        "browser launch page register",
    )
    text = replace_once(
        text,
        "                \"pages\": len(self.pages),\n"
        "                \"profile\": profile_info,\n",
        "                \"pages\": len(self.pages),\n"
        "                \"active_page_id\": self.active_page_id,\n"
        "                \"profile\": profile_info,\n",
        "browser launch diagnostics page id",
    )
    text = replace_once(
        text,
        "                \"pages\": list(self.pages.keys()),\n"
        "                \"window_width\": window_size[0],\n",
        "                \"session_id\": self.session_id,\n"
        "                \"active_page\": self.active_page_id,\n"
        "                \"active_page_id\": self.active_page_id,\n"
        "                \"page_count\": len(self.pages),\n"
        "                \"pages\": await self.list_pages(),\n"
        "                \"window_width\": window_size[0],\n",
        "browser launch result pages",
    )
    text = text.replace(
        "            self.pages.clear()\n"
        "            self.active_page_name = None\n",
        "            self.pages.clear()\n"
        "            self.page_meta.clear()\n"
        "            self.context_ids.clear()\n"
        "            self._page_guid_to_id.clear()\n"
        "            self._listener_page_ids.clear()\n"
        "            self.active_page_name = None\n"
        "            self.active_page_id = None\n",
    )
    helper_anchor = (
        "    def remove_persistent_script(self, name: str) -> bool:\n"
        "        \"\"\"Remove a persistent script by name. Returns True if found.\"\"\"\n"
        "        before = len(self._persistent_scripts)\n"
        "        self._persistent_scripts = [s for s in self._persistent_scripts if s[\"name\"] != name]\n"
        "        return len(self._persistent_scripts) < before\n\n"
    )
    helpers = r'''    def _page_guid(self, page: Page) -> str:
        impl = getattr(page, "_impl_obj", None)
        return str(getattr(page, "_guid", "") or getattr(impl, "_guid", "") or "")

    def _page_closed(self, page: Page) -> bool:
        try:
            return bool(page.is_closed())
        except Exception:
            return True

    def _slug(self, value: str | None) -> str:
        value = str(value or "page").strip().lower()
        value = _re.sub(r"[^a-z0-9_.:-]+", "-", value).strip("-")
        return value[:48] or "page"

    def _next_page_id(self, hint: str | None = None) -> str:
        base = self._slug(hint)
        while True:
            self._page_counter += 1
            candidate = f"{base}-{self._page_counter:04d}"
            if candidate not in self.pages and candidate not in self.page_meta:
                return candidate

    def _context_id_for_page(self, page: Page | None) -> str:
        if page is None:
            return "default"
        try:
            key = id(page.context)
            if key in self.context_ids:
                return self.context_ids[key]
        except Exception:
            pass
        return "default"

    def _register_context(self, context_id: str, ctx: BrowserContext) -> None:
        self.context_ids[id(ctx)] = context_id
        try:
            ctx.on("page", lambda page, cid=context_id: self._register_page(page, self._pop_pending_page_id(cid), True, "context_page", cid))
        except Exception as exc:
            _camoufox_debug("context_listener_failed", session_id=self.session_id, context_id=context_id, error_type=type(exc).__name__, error=_safe_text(exc, 300))
        _camoufox_debug("context_registered", session_id=self.session_id, context_id=context_id, pages=len(getattr(ctx, "pages", []) or []))

    def _queue_pending_page_id(self, context_id: str, page_id: str | None) -> None:
        pid = self._slug(page_id) if page_id else ""
        if pid:
            self._pending_page_ids_by_context.setdefault(context_id or "default", []).append(pid)

    def _pop_pending_page_id(self, context_id: str) -> str | None:
        queue = self._pending_page_ids_by_context.get(context_id or "default")
        if not queue:
            return None
        pid = queue.pop(0)
        if not queue:
            self._pending_page_ids_by_context.pop(context_id or "default", None)
        return pid

    def _discard_pending_page_id(self, context_id: str, page_id: str | None) -> None:
        pid = self._slug(page_id) if page_id else ""
        queue = self._pending_page_ids_by_context.get(context_id or "default")
        if pid and queue and pid in queue:
            queue.remove(pid)
            if not queue:
                self._pending_page_ids_by_context.pop(context_id or "default", None)

    def _register_page(self, page: Page, preferred_id: str | None = None, make_active: bool = False, source: str = "register", context_id: str | None = None) -> str:
        guid = self._page_guid(page)
        if guid and guid in self._page_guid_to_id:
            page_id = self._page_guid_to_id[guid]
        else:
            existing = None
            for pid, known in self.pages.items():
                if known is page:
                    existing = pid
                    break
            page_id = existing or (self._slug(preferred_id) if preferred_id and preferred_id not in self.pages and preferred_id not in self.page_meta else self._next_page_id(preferred_id))
        context_id = context_id or self._context_id_for_page(page)
        created = page_id not in self.pages
        self.pages[page_id] = page
        if guid:
            self._page_guid_to_id[guid] = page_id
        meta = self.page_meta.setdefault(page_id, {})
        meta.update({
            "page_id": page_id,
            "context_id": context_id,
            "guid": guid,
            "created_ms": meta.get("created_ms") or int(time.time() * 1000),
            "last_used_ms": int(time.time() * 1000),
            "closed": False,
            "source": source,
        })
        if page_id not in self._listener_page_ids:
            self._listener_page_ids.add(page_id)
            self._attach_listeners(page, page_id)
        if make_active or not self.active_page_id:
            self.active_page_id = page_id
            self.active_page_name = page_id
        _camoufox_debug("page_registered", session_id=self.session_id, page_id=page_id, context_id=context_id, guid=guid, created=created, active=self.active_page_id, source=source, page_count=len(self.pages))
        return page_id

    def _on_page_closed(self, page_id: str) -> None:
        page = self.pages.pop(page_id, None)
        meta = self.page_meta.setdefault(page_id, {"page_id": page_id})
        meta["closed"] = True
        meta["closed_ms"] = int(time.time() * 1000)
        guid = meta.get("guid") or (self._page_guid(page) if page else "")
        if guid:
            self._page_guid_to_id.pop(str(guid), None)
        if self.active_page_id == page_id:
            self.active_page_id = next(iter(self.pages.keys()), None)
            self.active_page_name = self.active_page_id
        _camoufox_debug("page_closed", session_id=self.session_id, page_id=page_id, active=self.active_page_id or "", page_count=len(self.pages))

    def page_id_for(self, page: Page | None) -> str | None:
        if page is None:
            return None
        guid = self._page_guid(page)
        if guid and guid in self._page_guid_to_id:
            return self._page_guid_to_id[guid]
        for pid, known in self.pages.items():
            if known is page:
                return pid
        return None

    async def page_summary(self, page: Page | None = None, page_id: str | None = None) -> dict[str, Any]:
        if page is None:
            page = await self.resolve_page(page_id)
        page_id = page_id or self.page_id_for(page) or self._register_page(page, None, False, "summary")
        meta = dict(self.page_meta.get(page_id, {}))
        url = ""
        title = ""
        closed = True
        title_error = None
        try:
            closed = self._page_closed(page)
            if not closed:
                url = str(page.url or "")
                try:
                    title = await asyncio.wait_for(page.title(), timeout=3)
                except Exception as exc:
                    title_error = _safe_text(exc, 300)
        except Exception as exc:
            title_error = _safe_text(exc, 300)
        out = {
            "session_id": self.session_id,
            "page_id": page_id,
            "context_id": meta.get("context_id") or self._context_id_for_page(page),
            "active": page_id == self.active_page_id,
            "closed": closed,
            "url": url,
            "title": title,
            "guid": meta.get("guid") or self._page_guid(page),
            "created_ms": meta.get("created_ms"),
            "last_used_ms": meta.get("last_used_ms"),
        }
        if title_error:
            out["title_error"] = title_error
        return out

    async def page_envelope(self, page: Page | None = None, page_id: str | None = None) -> dict[str, Any]:
        if page is None:
            page = await self.resolve_page(page_id)
        pid = self.page_id_for(page) or page_id or self._register_page(page, None, False, "envelope")
        summary = await self.page_summary(page, pid)
        return {
            "session_id": self.session_id,
            "page_id": pid,
            "active_page_id": self.active_page_id,
            "page_count": len(self.pages),
            "url": summary.get("url", ""),
            "title": summary.get("title", ""),
        }

    async def list_pages(self) -> list[dict[str, Any]]:
        await self._ensure_browser()
        out = []
        for page_id, page in list(self.pages.items()):
            out.append(await self.page_summary(page, page_id))
        _camoufox_debug("pages_listed", session_id=self.session_id, active_page_id=self.active_page_id or "", page_count=len(out))
        return out

    async def new_page(self, url: str | None = None, page_id: str | None = None, make_active: bool = True, context_id: str | None = None) -> dict[str, Any]:
        await self._ensure_browser()
        requested_context_id = context_id or "default"
        ctx = self.contexts.get(requested_context_id) or await self.get_active_context()
        requested_context_id = context_id or self.context_ids.get(id(ctx), "default")
        self._queue_pending_page_id(requested_context_id, page_id)
        try:
            page = await ctx.new_page()
        except Exception:
            self._discard_pending_page_id(requested_context_id, page_id)
            raise
        privacy_info = await _verify_private_page(page)
        privacy_page_id = self.page_id_for(page) or (page_id or "")
        _camoufox_debug("page_privacy_verified", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)
        if not privacy_info.get("webrtc_disabled"):
            with contextlib.suppress(Exception):
                await page.close()
            raise RuntimeError("Camoufox privacy verification failed: WebRTC is still exposed")
        pid = self._register_page(page, page_id, make_active, "new_page", requested_context_id)
        self._discard_pending_page_id(requested_context_id, page_id)
        if url:
            await page.goto(url, wait_until="load", timeout=30000)
        summary = await self.page_summary(page, pid)
        _camoufox_debug("page_created", session_id=self.session_id, page_id=pid, active_page_id=self.active_page_id or "", url_len=len(summary.get("url", "")), page_count=len(self.pages))
        return {"status": "created", "page": summary, "page_id": pid, "active_page_id": self.active_page_id, "page_count": len(self.pages)}

    async def select_page(self, page_id: str) -> dict[str, Any]:
        page = await self.resolve_page(page_id)
        pid = self.page_id_for(page) or page_id
        self.active_page_id = pid
        self.active_page_name = pid
        meta = self.page_meta.setdefault(pid, {"page_id": pid})
        meta["last_used_ms"] = int(time.time() * 1000)
        summary = await self.page_summary(page, pid)
        _camoufox_debug("page_selected", session_id=self.session_id, page_id=pid, url_len=len(summary.get("url", "")), page_count=len(self.pages))
        return {"status": "selected", "page": summary, "page_id": pid, "active_page_id": self.active_page_id, "page_count": len(self.pages)}

    async def close_page(self, page_id: str) -> dict[str, Any]:
        page = await self.resolve_page(page_id)
        pid = self.page_id_for(page) or page_id
        await page.close()
        self._on_page_closed(pid)
        return {"status": "closed", "page_id": pid, "active_page_id": self.active_page_id, "page_count": len(self.pages)}

    async def resolve_page(self, page_id: str | None = None) -> Page:
        await self._ensure_browser()
        pid = str(page_id or self.active_page_id or self.active_page_name or "default")
        page = self.pages.get(pid)
        if page is None and pid == "active" and self.active_page_id:
            page = self.pages.get(self.active_page_id)
            pid = self.active_page_id
        if page is None and not page_id and self.pages:
            pid, page = next(iter(self.pages.items()))
        if page is None:
            raise RuntimeError(f"No page available for page_id={pid!r}. Call launch_browser or new_page first.")
        if self._page_closed(page):
            self._on_page_closed(pid)
            raise RuntimeError(f"Page is closed: {pid}")
        self.active_page_id = pid if not page_id else self.active_page_id
        self.active_page_name = self.active_page_id
        self.page_meta.setdefault(pid, {"page_id": pid})["last_used_ms"] = int(time.time() * 1000)
        return page

'''
    text = replace_once(text, helper_anchor, helper_anchor + helpers, "browser helper insertion")
    text = replace_once(
        text,
        "    def _attach_listeners(self, page: Page) -> None:\n"
        "        \"\"\"Attach console, network, and trace-collection listeners to a page.\"\"\"\n"
        "        page.on(\"console\", self._on_console)\n"
        "        page.on(\"request\", self._on_request)\n"
        "        page.on(\"response\", self._on_response_async)\n"
        "        page.on(\"response\", self._on_response_for_nav)\n",
        "    def _attach_listeners(self, page: Page, page_id: str | None = None) -> None:\n"
        "        page_id = page_id or self.page_id_for(page) or self._register_page(page, None, False, \"listener_attach\")\n"
        "        page.on(\"console\", lambda msg, pid=page_id: self._on_console(msg, pid))\n"
        "        page.on(\"request\", lambda req, pid=page_id: self._on_request(req, pid))\n"
        "        page.on(\"response\", lambda resp, pid=page_id: self._on_response_async(resp, pid))\n"
        "        page.on(\"response\", lambda resp, pid=page_id: self._on_response_for_nav(resp, pid))\n"
        "        page.on(\"close\", lambda *_, pid=page_id: self._on_page_closed(pid))\n"
        "        with contextlib.suppress(Exception):\n"
        "            page.on(\"crash\", lambda *_, pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid))\n",
        "browser attach listeners",
    )
    text = replace_once(
        text,
        "    def _on_console(self, msg) -> None:\n",
        "    def _on_console(self, msg, page_id: str | None = None) -> None:\n",
        "browser console signature",
    )
    text = replace_once(
        text,
        "            \"timestamp\": int(time.time() * 1000),\n"
        "            \"location\": str(msg.location) if hasattr(msg, \"location\") else None,\n",
        "            \"timestamp\": int(time.time() * 1000),\n"
        "            \"page_id\": page_id,\n"
        "            \"context_id\": self.page_meta.get(page_id or \"\", {}).get(\"context_id\"),\n"
        "            \"location\": str(msg.location) if hasattr(msg, \"location\") else None,\n",
        "browser console fields",
    )
    text = replace_once(
        text,
        "    def _on_request(self, req) -> None:\n",
        "    def _on_request(self, req, page_id: str | None = None) -> None:\n",
        "browser request signature",
    )
    text = replace_once(
        text,
        "            \"id\": self._request_id_counter,\n"
        "            \"url\": req.url,\n",
        "            \"id\": self._request_id_counter,\n"
        "            \"page_id\": page_id,\n"
        "            \"context_id\": self.page_meta.get(page_id or \"\", {}).get(\"context_id\"),\n"
        "            \"url\": req.url,\n",
        "browser request fields",
    )
    text = replace_once(
        text,
        "    def _on_response_async(self, resp) -> None:\n"
        "        \"\"\"Handle response events, optionally capturing body asynchronously.\"\"\"\n",
        "    def _on_response_async(self, resp, page_id: str | None = None) -> None:\n",
        "browser response signature",
    )
    text = replace_once(
        text,
        "            if entry[\"url\"] == resp.url and entry[\"status\"] is None:\n",
        "            if entry[\"url\"] == resp.url and entry[\"status\"] is None and (page_id is None or entry.get(\"page_id\") == page_id):\n",
        "browser response page match",
    )
    text = replace_once(
        text,
        "    def _on_response_for_nav(self, resp) -> None:\n"
        "        \"\"\"Record every response during a navigation for final_status resolution.\"\"\"\n"
        "        try:\n"
        "            self._nav_responses.append({\n"
        "                \"url\": resp.url,\n"
        "                \"status\": resp.status,\n"
        "                \"resource_type\": getattr(resp.request, \"resource_type\", None) if resp.request else None,\n"
        "                \"ts\": int(time.time() * 1000),\n"
        "            })\n"
        "            # Keep only the last 100\n"
        "            if len(self._nav_responses) > 100:\n"
        "                self._nav_responses = self._nav_responses[-100:]\n"
        "        except Exception:\n"
        "            pass\n\n"
        "    def reset_nav_responses(self) -> None:\n"
        "        self._nav_responses = []\n",
        "    def _on_response_for_nav(self, resp, page_id: str | None = None) -> None:\n"
        "        try:\n"
        "            entry = {\n"
        "                \"url\": resp.url,\n"
        "                \"status\": resp.status,\n"
        "                \"resource_type\": getattr(resp.request, \"resource_type\", None) if resp.request else None,\n"
        "                \"page_id\": page_id,\n"
        "                \"ts\": int(time.time() * 1000),\n"
        "            }\n"
        "            self._nav_responses.append(entry)\n"
        "            if page_id:\n"
        "                page_chain = self._nav_responses_by_page.setdefault(page_id, [])\n"
        "                page_chain.append(entry)\n"
        "                if len(page_chain) > 100:\n"
        "                    self._nav_responses_by_page[page_id] = page_chain[-100:]\n"
        "            if len(self._nav_responses) > 100:\n"
        "                self._nav_responses = self._nav_responses[-100:]\n"
        "        except Exception:\n"
        "            pass\n\n"
        "    def reset_nav_responses(self, page_id: str | None = None) -> None:\n"
        "        if page_id:\n"
        "            self._nav_responses_by_page[page_id] = []\n"
        "            self._nav_responses = [r for r in self._nav_responses if r.get(\"page_id\") != page_id]\n"
        "        else:\n"
        "            self._nav_responses = []\n"
        "            self._nav_responses_by_page.clear()\n\n"
        "    def nav_responses_for_page(self, page_id: str | None = None) -> list[dict]:\n"
        "        if page_id:\n"
        "            return list(self._nav_responses_by_page.get(page_id, []))\n"
        "        return list(self._nav_responses)\n",
        "browser nav response methods",
    )
    text = replace_once(
        text,
        "        self.contexts[name] = ctx\n"
        "        page = await ctx.new_page()\n"
        "        self._attach_listeners(page)\n"
        "        self.pages[name] = page\n"
        "        self.active_page_name = name\n"
        "        return {\"status\": \"created\", \"context\": name, \"mode\": mode}\n",
        "        self.contexts[name] = ctx\n"
        "        self._register_context(name, ctx)\n"
        "        page = await ctx.new_page()\n"
        "        page_id = self._register_page(page, name, True, \"create_context\", name)\n"
        "        return {\"status\": \"created\", \"context\": name, \"mode\": mode, \"page_id\": page_id, \"active_page_id\": self.active_page_id, \"page_count\": len(self.pages)}\n",
        "browser create_context page register",
    )
    text = replace_once(
        text,
        "        if self.active_page_name and self.active_page_name in self.pages:\n"
        "            return self.pages[self.active_page_name].context\n",
        "        if self.active_page_id and self.active_page_id in self.pages:\n"
        "            return self.pages[self.active_page_id].context\n",
        "browser active context",
    )
    text = replace_once(
        text,
        "        if self.active_page_name and self.active_page_name in self.pages:\n"
        "            return self.pages[self.active_page_name]\n"
        "        raise RuntimeError(\"No active page available. Call launch_browser first.\")\n",
        "        return await self.resolve_page(None)\n",
        "browser get active page",
    )
    text = text.replace(
        "        self._nav_responses.clear()\n"
        "        self._route_handlers.clear()\n",
        "        self._nav_responses.clear()\n"
        "        self._nav_responses_by_page.clear()\n"
        "        self._route_handlers.clear()\n",
    )
    for marker in ("self._aida_multipage_patch = 4", "async def list_pages", "async def resolve_page", "page_id", "active_page_id", "_pending_page_ids_by_context", "page_privacy_verified"):
        if marker not in text:
            fail(f"browser validation missing {marker}")
    write_text(path, text)


def patch_navigation(path: pathlib.Path) -> None:
    text = read_text(path)
    if "async def list_pages(" in text and "page_id: str | None = None" in text:
        text = patch_navigation_capture(path, text)
        text = patch_navigation_diagnostics(path, text)
        write_text(path, text)
        return
    text = replace_once(
        text,
        "@mcp.tool()\nasync def close_browser() -> dict:\n    \"\"\"Close the Camoufox browser and release all resources.\"\"\"\n    try:\n        return await browser_manager.close()\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n",
        "@mcp.tool()\nasync def close_browser() -> dict:\n    \"\"\"Close the Camoufox browser and release all resources.\"\"\"\n    try:\n        return await browser_manager.close()\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n"
        "@mcp.tool()\nasync def list_pages() -> dict:\n    try:\n        pages = await browser_manager.list_pages()\n        return {\"session_id\": browser_manager.session_id, \"active_page_id\": browser_manager.active_page_id, \"page_count\": len(pages), \"pages\": pages}\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n"
        "@mcp.tool()\nasync def new_page(url: str | None = None, page_id: str | None = None, make_active: bool = True) -> dict:\n    try:\n        return await browser_manager.new_page(url=url, page_id=page_id, make_active=make_active)\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n"
        "@mcp.tool()\nasync def select_page(page_id: str) -> dict:\n    try:\n        return await browser_manager.select_page(page_id)\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n"
        "@mcp.tool()\nasync def close_page(page_id: str) -> dict:\n    try:\n        return await browser_manager.close_page(page_id)\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n",
        "navigation page tool insertion",
    )
    text = text.replace(
        "async def navigate(\n"
        "    url: str,\n",
        "async def navigate(\n"
        "    url: str,\n"
        "    page_id: str | None = None,\n",
    )
    text = text.replace("        page = await browser_manager.get_active_page()\n", "        page = await browser_manager.resolve_page(page_id)\n")
    text = text.replace("            browser_manager.reset_nav_responses()\n", "            browser_manager.reset_nav_responses(page_id)\n")
    text = text.replace("            chain = list(browser_manager._nav_responses)\n", "            chain = browser_manager.nav_responses_for_page(page_id)\n")
    text = replace_once(
        text,
        "        if title_error:\n            out[\"title_error\"] = title_error\n        return out\n\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\nasync def _inject_hook_by_name",
        "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\nasync def _inject_hook_by_name",
        "navigation navigate envelope",
    )
    text = text.replace("async def reload(wait_until: str = \"load\") -> dict:", "async def reload(wait_until: str = \"load\", page_id: str | None = None) -> dict:")
    reload_old = "        if title_error:\n            out[\"title_error\"] = title_error\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot"
    reload_new = "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot"
    reload_raw = "        await page.goto(current_url, wait_until=wait_until)\n        return {\"url\": page.url, \"title\": await page.title()}\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot"
    reload_raw_new = "        await page.goto(current_url, wait_until=wait_until)\n        title = \"\"\n        title_error = None\n        try:\n            title = await page.title()\n        except Exception as e:\n            title_error = str(e)\n        out = {\"url\": page.url, \"title\": title}\n        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot"
    if reload_old in text:
        text = text.replace(reload_old, reload_new, 1)
    elif reload_raw in text:
        text = text.replace(reload_raw, reload_raw_new, 1)
    elif "out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot" not in text:
        fail(f"navigation reload envelope anchor missing {path}")
    text = text.replace("async def take_screenshot(full_page: bool = False, selector: str | None = None) -> dict:", "async def take_screenshot(full_page: bool = False, selector: str | None = None, page_id: str | None = None) -> dict:")
    text = replace_once(
        text,
        "        return {\"screenshot_base64\": base64.b64encode(data).decode(), \"format\": \"png\"}\n",
        "        out = {\"screenshot_base64\": base64.b64encode(data).decode(), \"format\": \"png\"}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
        "navigation screenshot envelope",
    )
    text = text.replace("async def take_snapshot() -> dict:", "async def take_snapshot(page_id: str | None = None) -> dict:")
    text = replace_once(
        text,
        "        return {\"snapshot\": snapshot}\n",
        "        out = {\"snapshot\": snapshot}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
        "navigation snapshot envelope",
    )
    text = text.replace("async def click(selector: str) -> dict:", "async def click(selector: str, page_id: str | None = None) -> dict:")
    text = replace_once(
        text,
        "        await page.click(selector)\n        return {\"status\": \"clicked\", \"selector\": selector}\n",
        "        await page.click(selector)\n        out = {\"status\": \"clicked\", \"selector\": selector}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
        "navigation click envelope",
    )
    text = text.replace("async def type_text(selector: str, text: str, delay: int = 50) -> dict:", "async def type_text(selector: str, text: str, delay: int = 50, page_id: str | None = None) -> dict:")
    text = replace_once(
        text,
        "        await page.type(selector, text, delay=delay)\n        return {\"status\": \"typed\", \"selector\": selector, \"text\": text}\n",
        "        await page.type(selector, text, delay=delay)\n        out = {\"status\": \"typed\", \"selector\": selector, \"text\": text}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
        "navigation type envelope",
    )
    text = text.replace(
        "async def wait_for(\n    selector: str | None = None,\n    url_pattern: str | None = None,\n    timeout: int = 30000,\n) -> dict:",
        "async def wait_for(\n    selector: str | None = None,\n    url_pattern: str | None = None,\n    timeout: int = 30000,\n    page_id: str | None = None,\n) -> dict:",
    )
    text = replace_once(
        text,
        "            await page.wait_for_selector(selector, timeout=timeout)\n            return {\"status\": \"found\", \"selector\": selector}\n",
        "            await page.wait_for_selector(selector, timeout=timeout)\n            out = {\"status\": \"found\", \"selector\": selector}\n            out.update(await browser_manager.page_envelope(page))\n            return out\n",
        "navigation wait selector envelope",
    )
    text = replace_once(
        text,
        "            await page.wait_for_url(url_pattern, timeout=timeout)\n            return {\"status\": \"matched\", \"url_pattern\": url_pattern}\n",
        "            await page.wait_for_url(url_pattern, timeout=timeout)\n            out = {\"status\": \"matched\", \"url_pattern\": url_pattern}\n            out.update(await browser_manager.page_envelope(page))\n            return out\n",
        "navigation wait url envelope",
    )
    text = text.replace("async def get_page_info() -> dict:", "async def get_page_info(page_id: str | None = None) -> dict:")
    page_info_old = "        if title_error:\n            out[\"title_error\"] = title_error\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state"
    page_info_new = "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state"
    page_info_raw = "        bounds = await browser_manager._page_bounds(page)\n        return {\n            \"url\": page.url, \"title\": await page.title(),\n            \"viewport_width\": viewport.get(\"width\"),\n            \"viewport_height\": viewport.get(\"height\"),\n            \"window_bounds\": bounds,\n        }\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state"
    page_info_raw_new = "        bounds = await browser_manager._page_bounds(page)\n        title = \"\"\n        title_error = None\n        try:\n            title = await page.title()\n        except Exception as e:\n            title_error = str(e)\n        out = {\n            \"url\": page.url, \"title\": title,\n            \"viewport_width\": viewport.get(\"width\"),\n            \"viewport_height\": viewport.get(\"height\"),\n            \"window_bounds\": bounds,\n        }\n        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state"
    if page_info_old in text:
        text = text.replace(page_info_old, page_info_new, 1)
    elif page_info_raw in text:
        text = text.replace(page_info_raw, page_info_raw_new, 1)
    elif "out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state" not in text:
        fail(f"navigation page info envelope anchor missing {path}")
    if "async def list_pages(" not in text or "page_id: str | None = None" not in text:
        fail(f"navigation validation failed {path}")
    text = patch_navigation_capture(path, text)
    text = patch_navigation_diagnostics(path, text)
    write_text(path, text)


def patch_debugging(path: pathlib.Path) -> None:
    text = read_text(path)
    if "playwright_evaluate_signature" not in text:
        text = replace_once(
            text,
            "    # Timeout\n    elif \"timeout\" in error_msg.lower() or \"exceeded\" in error_msg.lower():\n",
            "    elif \"takes exactly\" in error_msg.lower() and \"argument\" in error_msg.lower():\n"
            "        hint = (\n"
            "            \"The JavaScript expression or browser callback was invoked with the wrong arity. \"\n"
            "            \"evaluate_js expects expression, await_promise, and optional page_id; \"\n"
            "            \"inspect the target function's name and length before calling it, or call it with all required parameters inside an IIFE.\"\n"
            "        )\n"
            "    # Timeout\n    elif \"timeout\" in error_msg.lower() or \"exceeded\" in error_msg.lower():\n",
            "debugging arity hint",
        )
        text = replace_once(
            text,
            "    return {\n"
            "        \"type\": \"error\",\n"
            "        \"error\": error_msg,\n"
            "        \"hint\": hint,\n"
            "    }\n",
            "    return {\n"
            "        \"type\": \"error\",\n"
            "        \"error\": error_msg,\n"
            "        \"hint\": hint,\n"
            "        \"playwright_evaluate_signature\": \"page.evaluate(expression, arg?)\",\n"
            "        \"mcp_arguments\": [\"expression\", \"await_promise\", \"page_id\"],\n"
            "    }\n",
            "debugging error signature metadata",
        )
    if "async def evaluate_js(expression: str, await_promise: bool = True, page_id: str | None = None)" not in text:
        text = replace_once(
            text,
            "async def evaluate_js(expression: str, await_promise: bool = True) -> dict:",
            "async def evaluate_js(expression: str, await_promise: bool = True, page_id: str | None = None) -> dict:",
            "debugging evaluate signature",
        )
        text = replace_once(text, "        page = await browser_manager.get_active_page()\n", "        page = await browser_manager.resolve_page(page_id)\n", "debugging page resolve")
        text = replace_once(
            text,
            "        if isinstance(raw, dict) and \"error\" in raw:\n",
            "        envelope = await browser_manager.page_envelope(page)\n\n        if isinstance(raw, dict) and \"error\" in raw:\n",
            "debugging envelope local",
        )
    if "                    **(await browser_manager.page_envelope(page)),\n" not in text:
        text = re.sub(
            r'(\n[ \t]+"warnings": \[f"direct evaluate failed, used handle fallback: \{msg\[:200\]\}"\],\n)([ \t]+)\}',
            r'\1\2**(await browser_manager.page_envelope(page)),\n\2}',
            text,
            count=1,
        )
    text = text.replace(
        "                    \"warnings\": [\n                        f\"Expression returned a Symbol ({symbol_desc}). \"\n                        \"Symbols are not JSON-serializable; value is None.\"\n                    ],\n                }\n",
        "                    \"warnings\": [\n                        f\"Expression returned a Symbol ({symbol_desc}). \"\n                        \"Symbols are not JSON-serializable; value is None.\"\n                    ],\n                    **envelope,\n                }\n",
    )
    text = text.replace(
        "                    \"warnings\": [\n                        \"Expression returned undefined. If unintended, \"\n                        \"wrap logic in IIFE with explicit return: \"\n                        \"(() => { /* logic */; return <your_value>; })()\"\n                    ],\n                }\n",
        "                    \"warnings\": [\n                        \"Expression returned undefined. If unintended, \"\n                        \"wrap logic in IIFE with explicit return: \"\n                        \"(() => { /* logic */; return <your_value>; })()\"\n                    ],\n                    **envelope,\n                }\n",
    )
    text = text.replace(
        "                \"warnings\": None,\n            }\n",
        "                \"warnings\": None,\n                **envelope,\n            }\n",
        1,
    )
    text = text.replace(
        "                    \"warnings\": warnings_list if warnings_list else None,\n                }\n",
        "                    \"warnings\": warnings_list if warnings_list else None,\n                    **envelope,\n                }\n",
        1,
    )
    text = text.replace(
        "                \"warnings\": warnings_list if warnings_list else None,\n            }\n",
        "                \"warnings\": warnings_list if warnings_list else None,\n                **envelope,\n            }\n",
        1,
    )
    text = text.replace(
        "            \"warnings\": warnings_list if warnings_list else None,\n        }\n",
        "            \"warnings\": warnings_list if warnings_list else None,\n            **envelope,\n        }\n",
        1,
    )
    if "page_id: str | None = None" not in text or "browser_manager.resolve_page(page_id)" not in text:
        fail(f"debugging validation failed {path}")
    write_text(path, text)


def patch_network(path: pathlib.Path) -> None:
    text = read_text(path)
    if "page_id: str | None = None," in text and "\"page_id\": r.get(\"page_id\")" in text:
        return
    text = replace_once(
        text,
        "async def list_network_requests(\n"
        "    url_filter: str | None = None,\n",
        "async def list_network_requests(\n"
        "    page_id: str | None = None,\n"
        "    url_filter: str | None = None,\n",
        "network list signature",
    )
    text = replace_once(
        text,
        "        if url_filter:\n",
        "        if page_id:\n            reqs = [r for r in reqs if r.get(\"page_id\") == page_id]\n        if url_filter:\n",
        "network page filter",
    )
    text = replace_once(
        text,
        "                \"id\": r[\"id\"], \"url\": r[\"url\"][:200], \"method\": r[\"method\"],\n"
        "                \"status\": r.get(\"status\"), \"type\": r.get(\"resource_type\"),\n",
        "                \"id\": r[\"id\"], \"page_id\": r.get(\"page_id\"), \"context_id\": r.get(\"context_id\"),\n"
        "                \"url\": r[\"url\"][:200], \"method\": r[\"method\"],\n"
        "                \"status\": r.get(\"status\"), \"type\": r.get(\"resource_type\"),\n",
        "network summary page fields",
    )
    text = replace_once(
        text,
        "            \"count\": len(summaries),\n"
        "            \"capturing\": browser_manager._capturing,\n",
        "            \"count\": len(summaries),\n"
        "            \"page_id\": page_id,\n"
        "            \"active_page_id\": browser_manager.active_page_id,\n"
        "            \"page_count\": len(browser_manager.pages),\n"
        "            \"capturing\": browser_manager._capturing,\n",
        "network list envelope",
    )
    text = replace_once(
        text,
        "async def get_request_initiator(request_id: int) -> dict:",
        "async def get_request_initiator(request_id: int, page_id: str | None = None) -> dict:",
        "network initiator signature",
    )
    text = replace_once(
        text,
        "        page = await browser_manager.get_active_page()\n",
        "        page = await browser_manager.resolve_page(page_id or target_entry.get(\"page_id\"))\n",
        "network initiator resolve",
    )
    text = replace_once(
        text,
        "            \"diagnostics\": result.get(\"diagnostics\"),\n",
        "            \"diagnostics\": result.get(\"diagnostics\"),\n            **(await browser_manager.page_envelope(page)),\n",
        "network initiator envelope",
    )
    text = replace_once(
        text,
        "async def intercept_request(\n"
        "    url_pattern: str,\n",
        "async def intercept_request(\n"
        "    url_pattern: str,\n"
        "    page_id: str | None = None,\n",
        "network intercept signature",
    )
    text = replace_once(
        text,
        "        page = await browser_manager.get_active_page()\n",
        "        page = await browser_manager.resolve_page(page_id)\n",
        "network intercept resolve",
    )
    text = text.replace(
        "                return {\"status\": \"stopped\", \"pattern\": url_pattern}\n",
        "                out = {\"status\": \"stopped\", \"pattern\": url_pattern}\n                out.update(await browser_manager.page_envelope(page))\n                return out\n",
        1,
    )
    text = text.replace(
        "        return {\"status\": \"intercepting\", \"pattern\": url_pattern, \"action\": action}\n",
        "        out = {\"status\": \"intercepting\", \"pattern\": url_pattern, \"action\": action}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
    )
    if "\"page_id\": r.get(\"page_id\")" not in text or "browser_manager.resolve_page(page_id" not in text:
        fail(f"network validation failed {path}")
    write_text(path, text)


def patch_navigation_diagnostics(path: pathlib.Path, text: str) -> str:
    if "navigate_goto_exception" in text:
        return text
    if "import time\n" not in text:
        text = replace_once(text, "import os\n", "import os\nimport time\n", "navigation time import")
    if "import traceback as _traceback\n" not in text:
        text = replace_once(text, "import time\n", "import time\nimport traceback as _traceback\n", "navigation traceback import")
    if "from urllib.parse import urlsplit as _urlsplit\n" not in text:
        text = replace_once(text, "import traceback as _traceback\n", "import traceback as _traceback\nfrom urllib.parse import urlsplit as _urlsplit\n", "navigation urlsplit import")
    if "from ..browser import _camoufox_debug" not in text:
        text = replace_once(
            text,
            "from ..server import mcp, browser_manager\n",
            "from ..server import mcp, browser_manager\nfrom ..browser import _camoufox_debug, _safe_text, _windows_descendant_pids\n",
            "navigation debug import",
        )
    helpers = '''def _navigation_url_diag(url: str | None) -> dict:
    text = str(url or "")
    try:
        parsed = _urlsplit(text)
        return {
            "url_len": len(text),
            "url_scheme": parsed.scheme,
            "url_host": parsed.hostname or "",
            "url_path_len": len(parsed.path or ""),
            "url_query_len": len(parsed.query or ""),
        }
    except Exception as exc:
        return {"url_len": len(text), "url_parse_error": _safe_text(exc, 240)}


async def _navigation_state(page=None, requested_page_id: str | None = None) -> dict:
    state = {
        "session_id": getattr(browser_manager, "session_id", ""),
        "requested_page_id": requested_page_id or "",
        "active_page_id": getattr(browser_manager, "active_page_id", "") or "",
        "page_count": len(getattr(browser_manager, "pages", {}) or {}),
        "context_count": len(getattr(browser_manager, "contexts", {}) or {}),
        "browser_open": getattr(browser_manager, "browser", None) is not None,
    }
    try:
        descendants = _windows_descendant_pids(os.getpid())
        state["descendant_count"] = len(descendants)
        state["descendants"] = descendants[:24]
    except Exception as exc:
        state["descendant_error"] = _safe_text(exc, 240)
    if page is None:
        return state
    try:
        state["resolved_page_id"] = browser_manager.page_id_for(page) or ""
    except Exception as exc:
        state["resolved_page_error"] = _safe_text(exc, 240)
    try:
        closed = browser_manager._page_closed(page)
        state["page_closed"] = bool(closed)
    except Exception as exc:
        state["page_closed_error"] = _safe_text(exc, 240)
    try:
        current_url = str(getattr(page, "url", "") or "")
        parsed = _urlsplit(current_url)
        state["page_url_len"] = len(current_url)
        state["page_url_host"] = parsed.hostname or ""
    except Exception as exc:
        state["page_url_error"] = _safe_text(exc, 240)
    try:
        ctx = getattr(page, "context", None)
        state["context_pages"] = len(getattr(ctx, "pages", []) or []) if ctx is not None else 0
    except Exception as exc:
        state["context_pages_error"] = _safe_text(exc, 240)
    return state


'''
    if "async def _navigation_state" not in text:
        text = replace_once(text, "@mcp.tool()\nasync def launch_browser", helpers + "@mcp.tool()\nasync def launch_browser", "navigation diagnostics helpers")
    text = replace_once(
        text,
        "        page = await browser_manager.resolve_page(page_id)\n        warnings: list[str] = []\n",
        "        page = await browser_manager.resolve_page(page_id)\n        nav_started = time.perf_counter()\n        nav_url_diag = _navigation_url_diag(url)\n        nav_state = await _navigation_state(page, page_id)\n        warnings: list[str] = []\n        _camoufox_debug(\n            \"navigate_begin\",\n            wait_until=wait_until,\n            collect_response_chain=bool(collect_response_chain),\n            clear_network_capture=bool(clear_network_capture),\n            include_title=bool(include_title),\n            pre_inject_hooks=len(pre_inject_hooks or []),\n            **nav_url_diag,\n            **nav_state,\n        )\n",
        "navigation begin diagnostics",
    )
    text = replace_once(
        text,
        "        try:\n            resp = await page.goto(url, wait_until=wait_until, timeout=30000)\n        except Exception as e:\n            msg = str(e).lower()\n",
        "        try:\n            _camoufox_debug(\n                \"navigate_goto_begin\",\n                elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n                wait_until=wait_until,\n                **nav_url_diag,\n                **(await _navigation_state(page, page_id)),\n            )\n            resp = await page.goto(url, wait_until=wait_until, timeout=30000)\n            _camoufox_debug(\n                \"navigate_goto_ok\",\n                elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n                response_status=resp.status if resp else None,\n                **nav_url_diag,\n                **(await _navigation_state(page, page_id)),\n            )\n        except Exception as e:\n            _camoufox_debug(\n                \"navigate_goto_exception\",\n                elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n                wait_until=wait_until,\n                error_type=type(e).__name__,\n                error_summary=_safe_text(e, 1000),\n                error_repr=_safe_text(repr(e), 1000),\n                error_traceback=_safe_text(\"\".join(_traceback.format_exception(type(e), e, e.__traceback__)), 4000),\n                **nav_url_diag,\n                **(await _navigation_state(page, page_id)),\n            )\n            msg = str(e).lower()\n",
        "navigation goto diagnostics",
    )
    text = replace_once(
        text,
        "                        warnings.append(f\"page usable (readyState={dom_ready})\")\n                        resp = None\n                        navigation_timed_out = True\n",
        "                        warnings.append(f\"page usable (readyState={dom_ready})\")\n                        resp = None\n                        navigation_timed_out = True\n                        _camoufox_debug(\n                            \"navigate_goto_timeout_recovered\",\n                            elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n                            ready_state=str(dom_ready),\n                            **nav_url_diag,\n                            **(await _navigation_state(page, page_id)),\n                        )\n",
        "navigation timeout recovered diagnostics",
    )
    text = replace_once(
        text,
        "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\nasync def _inject_hook_by_name",
        "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        _camoufox_debug(\n            \"navigate_complete\",\n            elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n            initial_status=initial_status,\n            final_status=out.get(\"final_status\"),\n            navigation_timed_out=bool(navigation_timed_out),\n            warnings_count=len(warnings),\n            **nav_url_diag,\n            **(await _navigation_state(page, page_id)),\n        )\n        return out\n\n    except Exception as e:\n        err_page = locals().get(\"page\")\n        err_started = locals().get(\"nav_started\")\n        err_elapsed = int((time.perf_counter() - err_started) * 1000) if err_started else 0\n        err_url_diag = locals().get(\"nav_url_diag\") or _navigation_url_diag(url)\n        _camoufox_debug(\n            \"navigate_exception\",\n            elapsed_ms=err_elapsed,\n            wait_until=wait_until,\n            error_type=type(e).__name__,\n            error_summary=_safe_text(e, 1000),\n            error_repr=_safe_text(repr(e), 1000),\n            error_traceback=_safe_text(\"\".join(_traceback.format_exception(type(e), e, e.__traceback__)), 4000),\n            **err_url_diag,\n            **(await _navigation_state(err_page, page_id)),\n        )\n        return {\"error\": str(e)}\n\n\nasync def _inject_hook_by_name",
        "navigation completion diagnostics",
    )
    for marker in ("navigate_begin", "navigate_goto_begin", "navigate_goto_exception", "navigate_exception", "async def _navigation_state"):
        if marker not in text:
            fail(f"navigation diagnostics validation missing {marker} in {path}")
    return text


def patch_hooking(path: pathlib.Path) -> None:
    text = read_text(path)
    if "async def get_console_logs(" not in text:
        return
    if "page_id: str | None = None" in text and "log.get(\"page_id\") == page_id" in text:
        return
    text = replace_once(
        text,
        "async def get_console_logs(\n"
        "    level: str | None = None,\n",
        "async def get_console_logs(\n"
        "    page_id: str | None = None,\n"
        "    level: str | None = None,\n",
        "hooking console signature",
    )
    text = replace_once(
        text,
        "        if level:\n",
        "        if page_id:\n            logs = [log for log in logs if log.get(\"page_id\") == page_id]\n        if level:\n",
        "hooking console filter",
    )
    if "            \"count\": len(logs),\n" in text:
        text = replace_once(
            text,
            "            \"count\": len(logs),\n",
            "            \"count\": len(logs),\n            \"page_id\": page_id,\n            \"active_page_id\": browser_manager.active_page_id,\n            \"page_count\": len(browser_manager.pages),\n",
            "hooking console envelope",
        )
    write_text(path, text)


def main() -> None:
    if ROOT is None:
        fail("stage root argument is required")
    bases = [
        ROOT / "deps" / "camoufox-reverse-mcp" / "src" / "camoufox_reverse_mcp",
        ROOT / "deps" / "camoufox-runtime" / "Lib" / "site-packages" / "camoufox_reverse_mcp",
    ]
    patched = 0
    for base in bases:
        if not base.exists():
            continue
        patch_browser(base / "browser.py")
        patch_navigation(base / "tools" / "navigation.py")
        patch_debugging(base / "tools" / "debugging.py")
        patch_network(base / "tools" / "network.py")
        patch_hooking(base / "tools" / "hooking.py")
        patched += 1
    if patched == 0:
        fail(f"no camoufox_reverse_mcp package found under {ROOT}")
    print(f"Patched Camoufox reverse MCP multipage support in {patched} package copies")


if __name__ == "__main__":
    main()
