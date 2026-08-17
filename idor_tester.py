# -*- coding: utf-8 -*-
"""
IDOR Tester v1.0
================
A Burp Suite extension for AI-assisted IDOR/BOLA testing.

Learns candidate object-id fields from live Proxy traffic (URL, body, JSON,
XML, matrix/path params), swaps the attacker's id for the victim's, fires
the request, and scores the result (CONFIRMED / HIGH / MEDIUM) against a
clean baseline. Includes optional AI-assisted field extraction and
prompt-driven "Skills" for generating and running custom test strategies.

Repository: https://github.com/<your-username>/<your-repo>
License: MIT (see LICENSE)
"""

from burp import IBurpExtender, ITab, IHttpListener, IScanIssue, IParameter, IContextMenuFactory, IHttpRequestResponse
from java.awt import BorderLayout, Color, Font, FlowLayout, Dimension
from java.lang import Boolean
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JTextField, JLabel,
    JOptionPane, BorderFactory, BoxLayout, Box,
    JDialog, JTabbedPane, JTextArea, JSplitPane,
    JMenuItem, SwingUtilities, JTextPane,
    JComboBox, DefaultComboBoxModel, JCheckBox,
    JFileChooser, JPasswordField
)
from javax.swing.table import TableRowSorter, DefaultTableCellRenderer
from javax.swing import RowFilter
from java.awt.event import KeyAdapter
from javax.swing.table import DefaultTableModel
from java.util import ArrayList
import json
import re
import threading
import urllib
import urllib2
import time
import uuid
import difflib


class ResultsTableModel(DefaultTableModel):
    def getColumnClass(self, columnIndex):
        if columnIndex == 0:
            return int
        elif columnIndex == 4:
            return int
        elif columnIndex == 5:
            return int
        return str

class VulnRowRenderer(DefaultTableCellRenderer):
    """
    Colors an entire results-table row based on the "Vuln" column ("YES"/"NO"),
    so a vulnerable finding is immediately visible at a glance instead of
    requiring the analyst to scan the "Vuln" text column row by row.
    VULN_COL must match the index of the "Vuln" column in res_cols.
    """
    VULN_COL = 6

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        is_vuln = False
        try:
            model_row = table.convertRowIndexToModel(row)
            vuln_val = table.getModel().getValueAt(model_row, self.VULN_COL)
            is_vuln = str(vuln_val).upper() == "YES"
        except Exception:
            is_vuln = False
        if isSelected:
            comp.setBackground(table.getSelectionBackground())
            comp.setForeground(table.getSelectionForeground())
        elif is_vuln:
            comp.setBackground(Color(255, 210, 210))
            comp.setForeground(Color(120, 0, 0))
        else:
            comp.setBackground(Color.WHITE)
            comp.setForeground(Color.BLACK)
        return comp

class SimRenderer(VulnRowRenderer):
    def setValue(self, value):
        if value is not None:
            self.setText(str(value) + "%")
        else:
            self.setText("")

class CheckBoxTableModel(DefaultTableModel):
    def getColumnClass(self, columnIndex):
        if columnIndex == 0:
            return Boolean
        return str

    def isCellEditable(self, row, column):
        return column == 0


class CustomHttpRequestResponse(IHttpRequestResponse):
    def __init__(self, service, request, response, comment=None, highlight=None):
        self._http_service = service
        self._request = request
        self._response = response
        self._comment = comment
        self._highlight = highlight
    def getRequest(self): return self._request
    def setRequest(self, req): self._request = req
    def getResponse(self): return self._response
    def setResponse(self, resp): self._response = resp
    def getHttpService(self): return self._http_service
    def setHttpService(self, svc): self._http_service = svc
    def getComment(self): return self._comment
    def setComment(self, c): self._comment = c
    def getHighlight(self): return self._highlight
    def setHighlight(self, h): self._highlight = h


class IDORScanIssue(IScanIssue):
    def __init__(self, http_service, url, name, detail, severity, confidence, http_messages):
        self._http_service = http_service
        self._url = url
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._http_messages = http_messages
    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return self._severity
    def getConfidence(self): return self._confidence
    def getIssueBackground(self): return "IDOR occurs when an application exposes internal object references without proper access control."
    def getRemediationBackground(self): return "Implement server-side authorization checks for every object access."
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return "Verify user permissions before returning object data."
    def getHttpMessages(self): return self._http_messages
    def getHttpService(self): return self._http_service


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("IDOR Tester v1.0")

        self._lock = threading.Lock()
        self._attacker_id = ""
        self._victim_id = ""
        self._fields = []
        self._results = []
        self._test_count = 0
        self._vuln_count = 0
        self._last_message = None
        self._auto_test_enabled = False
        self._auto_extract_enabled = False
        self._scope_check_enabled = True
        self._processed_urls = set()
        self._id_pool = {}
        self._selected_keys = set()
        self._key_id_mapping = {}
        self._ai_enabled = False
        self._ai_verify_enabled = False
        self._ai_provider = "OpenRouter"
        self._ai_model = "openai/gpt-oss-20b:free"
        self._html_skip_issue = False

        # AI Skills system
        self._skills = []
        self._load_default_skills()
        self._load_skills_from_settings()

        # Strong deny keywords: unambiguous authorization-denial phrases.
        # A single hit here is enough to treat the response as "blocked".
        self._deny_keywords = [
            "permission denied", "access denied", "unauthorized", "forbidden",
            "not allowed", "no access", "no permission", "not permitted",
            "not authorized", "have_no_permission", "no_permission",
            "not_allowed", "you do not have permission", "you don't have permission",
            "insufficient permission", "insufficient privilege"
        ]

        # Weak/ambiguous keywords: common in generic validation or business-logic
        # errors too, so a single hit is NOT enough on its own to mark a response
        # as "blocked" (see _check_deny_keywords). Kept separate to avoid false
        # negatives where a real IDOR leak happens to contain one of these words
        # in an unrelated field.
        self._weak_deny_keywords = [
            "restricted", "blocked", "invalid", "fail", "cannot",
            "unable to", "privilege", "denied"
        ]

        self._build_ui()
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerHttpListener(self)
        self._callbacks.printOutput("[+] IDOR Tester v1.0 loaded!")
        self._callbacks.printOutput("[+] AI Skills system ready. Open Skill Manager to define custom test strategies.")
        self._callbacks.printOutput("[+] Per-key manual Attacker/Victim ID override available in Select Keys.")
        self._callbacks.printOutput("[+] Pwnfox: red=Attacker, blue=Victim. Cross-account swaps only.")
        self._callbacks.printOutput("[+] Auto-label from X-Pwnfox-Color header enabled.")

    def _load_default_skills(self):
        defaults = [
            {
                "id": str(uuid.uuid4()),
                "name": "IDOR Boundary Testing",
                "description": "Tests IDOR boundaries using zero, negative, max_int, random IDs, and UUID mutations.",
                "enabled": True,
                "prompt": (
                    "You are an expert API security tester. Given the HTTP request below, generate a JSON array of 5 to 8 IDOR boundary tests. "
                    "For each test, specify: test_name, field (parameter name), location (URL/Body/Header), original_value, new_value, reason. "
                    "Test ideas: replace numeric IDs with 0, -1, 999999999, another random ID of same length, off-by-one (id+1/id-1), or flip UUID segments. "
                    "Only return a valid JSON array. No markdown. No explanations outside JSON."
                )
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Privilege Escalation Check",
                "description": "Detects privilege escalation by injecting admin/elevated role parameters.",
                "enabled": False,
                "prompt": (
                    "You are an expert security tester focused on privilege escalation. Analyze the HTTP request and generate a JSON array of tests. "
                    "Each test should try to add or modify parameters like role, is_admin, admin, privilege, access_level to escalate privileges. "
                    "Return format: [{\"test_name\":\"...\",\"field\":\"...\",\"location\":\"...\",\"original_value\":\"...\",\"new_value\":\"...\",\"reason\":\"...\"}]. "
                    "Only valid JSON array. No extra text."
                )
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Mass Assignment Detector",
                "description": "Tests for Mass Assignment by adding hidden fields like is_admin, role, balance.",
                "enabled": False,
                "prompt": (
                    "You are testing for Mass Assignment vulnerabilities. Given the HTTP request, generate a JSON array of tests that add or update "
                    "sensitive fields commonly protected from direct user modification (e.g., is_admin, role, permissions, balance, credits, tier). "
                    "Return only a valid JSON array with objects containing: test_name, field, location, original_value, new_value, reason. "
                    "If the body is JSON, show the exact key path. No markdown."
                )
            },
            {
                "id": str(uuid.uuid4()),
                "name": "BOLA Deep Scan",
                "description": "Deep BOLA scan using sibling IDs, parent IDs, and orphaned object references.",
                "enabled": True,
                "prompt": (
                    "You are a BOLA (Broken Object Level Authorization) specialist. Analyze the request and generate a JSON array of tests. "
                    "Try replacing object IDs with: sibling IDs (+1 or -1 from current), parent collection IDs, or completely unrelated object IDs. "
                    "Also try removing the ID parameter entirely or using null/empty values. "
                    "Return only valid JSON array: [{\"test_name\",\"field\",\"location\",\"original_value\",\"new_value\",\"reason\"}]. No markdown."
                )
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Custom Payload Injection",
                "description": "User-defined custom payload strategy for advanced scenarios.",
                "enabled": False,
                "prompt": (
                    "You are a custom security testing engine. Analyze the HTTP request and generate creative test cases based on the context. "
                    "Return a JSON array of tests with: test_name, field, location, original_value, new_value, reason. "
                    "Only return valid JSON. No explanations."
                )
            }
        ]
        self._skills = defaults

    def _load_skills_from_settings(self):
        try:
            saved = self._callbacks.loadExtensionSetting("idor_tester_skills")
            if saved:
                parsed = json.loads(saved)
                if isinstance(parsed, list) and len(parsed) > 0:
                    self._skills = parsed
                    self._callbacks.printOutput("[Skills] Loaded " + str(len(self._skills)) + " skills from settings.")
        except Exception as e:
            self._callbacks.printOutput("[Skills] Could not load saved skills: " + str(e))

    def _save_skills_to_settings(self):
        try:
            self._callbacks.saveExtensionSetting("idor_tester_skills", json.dumps(self._skills))
        except Exception as e:
            self._callbacks.printOutput("[Skills] Save error: " + str(e))

    def _build_ui(self):
        self._panel = JPanel(BorderLayout())
        self._panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBorder(BorderFactory.createTitledBorder("Configuration"))

        # --- Row 1: Detection & scope toggles, grouped together -----------
        detect_row = JPanel(FlowLayout(FlowLayout.LEFT))
        detect_row.setBorder(BorderFactory.createTitledBorder("Detection"))

        self._auto_extract_btn = JButton("Auto-Extract IDs: OFF", actionPerformed=self._toggle_auto_extract)
        self._auto_extract_btn.setFont(Font("Consolas", Font.BOLD, 12))
        self._auto_extract_btn.setForeground(Color(150, 0, 0))
        self._auto_extract_btn.setToolTipText("Passively learn key=value ID pairs from every request/response that passes through Burp (URL, body, path, JSON).")
        detect_row.add(self._auto_extract_btn)
        detect_row.add(Box.createHorizontalStrut(8))

        self._ai_btn = JButton("AI Extract: OFF", actionPerformed=self._toggle_ai)
        self._ai_btn.setFont(Font("Consolas", Font.BOLD, 12))
        self._ai_btn.setForeground(Color(150, 0, 0))
        self._ai_btn.setToolTipText("Use the configured AI provider to identify candidate ID fields in a loaded request. Requires an API key below.")
        detect_row.add(self._ai_btn)
        detect_row.add(Box.createHorizontalStrut(8))

        self._auto_test_btn = JButton("Auto-Test: OFF", actionPerformed=self._toggle_auto_test)
        self._auto_test_btn.setFont(Font("Consolas", Font.BOLD, 12))
        self._auto_test_btn.setForeground(Color(150, 0, 0))
        self._auto_test_btn.setToolTipText("Automatically fire IDOR swap tests on every matching in-scope request as it passes through Burp.")
        detect_row.add(self._auto_test_btn)
        detect_row.add(Box.createHorizontalStrut(8))

        self._scope_btn = JButton("Scope-Only: ON", actionPerformed=self._toggle_scope)
        self._scope_btn.setFont(Font("Consolas", Font.BOLD, 12))
        self._scope_btn.setForeground(Color(0, 150, 0))
        self._scope_btn.setToolTipText("When ON, passive extraction/testing only runs on requests inside Burp's defined target scope.")
        detect_row.add(self._scope_btn)
        detect_row.add(Box.createHorizontalStrut(8))

        self._html_btn = JButton("HTML Skip Issue: OFF", actionPerformed=self._toggle_html_skip)
        self._html_btn.setFont(Font("Consolas", Font.BOLD, 12))
        self._html_btn.setForeground(Color(150, 0, 0))
        self._html_btn.setToolTipText("When ON, a 'vulnerable' finding whose response is an HTML page will not auto-register a Burp Scanner issue (reduces noise from generic HTML error pages).")
        detect_row.add(self._html_btn)
        top.add(detect_row)

        # --- Row 2: Tools (pool / keys / skills / cache) -------------------
        tools_row = JPanel(FlowLayout(FlowLayout.LEFT))
        tools_row.setBorder(BorderFactory.createTitledBorder("Tools"))

        btn_pool = JButton("View ID Pool", actionPerformed=self._view_id_pool)
        btn_pool.setToolTipText("Show every ID learned so far, grouped by key name.")
        tools_row.add(btn_pool)
        tools_row.add(Box.createHorizontalStrut(8))

        btn_keys = JButton("Select Keys", actionPerformed=self._select_keys_dialog)
        btn_keys.setToolTipText("Choose which learned ID keys are actually used for passive auto-testing.")
        tools_row.add(btn_keys)
        tools_row.add(Box.createHorizontalStrut(8))

        btn_clear_cache = JButton("Clear Test Cache", actionPerformed=self._clear_test_cache)
        btn_clear_cache.setToolTipText("Forget which URLs were already auto-tested, so they get retested on next sight.")
        tools_row.add(btn_clear_cache)
        tools_row.add(Box.createHorizontalStrut(8))

        btn_skills = JButton("Skill Manager", actionPerformed=self._open_skill_manager)
        btn_skills.setFont(Font("Consolas", Font.BOLD, 12))
        btn_skills.setForeground(Color(0, 0, 150))
        btn_skills.setToolTipText("Create, edit, enable/disable AI-driven test strategies (skills).")
        tools_row.add(btn_skills)
        tools_row.add(Box.createHorizontalStrut(8))

        btn_run_skills = JButton("Run AI Skills", actionPerformed=self._run_skills_on_loaded)
        btn_run_skills.setFont(Font("Consolas", Font.BOLD, 12))
        btn_run_skills.setForeground(Color(0, 100, 0))
        btn_run_skills.setToolTipText("Run every enabled skill against the currently loaded request.")
        tools_row.add(btn_run_skills)
        top.add(tools_row)

        # --- Row 3: Attacker / Victim IDs ----------------------------------
        id_row = JPanel(FlowLayout(FlowLayout.LEFT))
        id_row.setBorder(BorderFactory.createTitledBorder("Attacker / Victim IDs"))
        self._atk_field = JTextField(20)
        self._atk_field.setToolTipText("The ID belonging to the account you are testing FROM (the attacker's own session/token).")
        self._vic_field = JTextField(20)
        self._vic_field.setToolTipText("The ID belonging to the account/object you should NOT be able to access (the victim).")
        btn_atk_from_pool = JButton("Set from Pool", actionPerformed=lambda e: self._set_id_from_pool("attacker"))
        btn_vic_from_pool = JButton("Set from Pool", actionPerformed=lambda e: self._set_id_from_pool("victim"))
        id_row.add(JLabel("Attacker ID:"))
        id_row.add(self._atk_field)
        id_row.add(btn_atk_from_pool)
        id_row.add(Box.createHorizontalStrut(10))
        id_row.add(JLabel("Victim ID:"))
        id_row.add(self._vic_field)
        id_row.add(btn_vic_from_pool)
        top.add(id_row)

        # --- Row 4: AI provider settings ------------------------------------
        ai_row = JPanel(FlowLayout(FlowLayout.LEFT))
        ai_row.setBorder(BorderFactory.createTitledBorder("AI Provider"))

        # Masked by default (JPasswordField) so the key isn't shown in plain
        # text on screen/screenshots/screen-shares. A Show/Hide toggle lets
        # the user verify what they typed when needed.
        self._ai_key_field = JPasswordField(35)
        self._ai_key_field.setEchoChar(u'\u2022')
        self._ai_key_field.setToolTipText("API Key for selected provider. Groq: console.groq.com | Anthropic: console.anthropic.com | OpenRouter: openrouter.ai | Kimi: platform.moonshot.cn")
        self._ai_key_label = JLabel("OpenRouter Key:")
        ai_row.add(self._ai_key_label)
        ai_row.add(self._ai_key_field)

        self._ai_key_show_btn = JButton("Show", actionPerformed=self._toggle_key_visibility)
        self._ai_key_show_btn.setToolTipText("Temporarily reveal the API key to verify it was typed correctly.")
        ai_row.add(self._ai_key_show_btn)

        btn_ai_test = JButton("Test API", actionPerformed=self._test_ai_key)
        btn_ai_test.setToolTipText("Send a tiny test request to confirm the key/provider/model combination works.")
        ai_row.add(btn_ai_test)
        ai_row.add(Box.createHorizontalStrut(8))
        self._ai_provider_combo = JComboBox(["OpenRouter", "Groq", "Anthropic", "Kimi"])
        self._ai_provider_combo.setSelectedItem(self._ai_provider)
        self._ai_provider_combo.addActionListener(lambda e: self._set_ai_provider())
        ai_row.add(JLabel("Provider:"))
        ai_row.add(self._ai_provider_combo)
        ai_row.add(Box.createHorizontalStrut(8))
        self._ai_model_combo = JComboBox(["openai/gpt-oss-20b:free", "nvidia/nemotron-3-ultra-550b-a55b:free"])
        self._ai_model_combo.setSelectedItem(self._ai_model)
        self._ai_model_combo.addActionListener(lambda e: self._set_ai_model())
        ai_row.add(JLabel("Model:"))
        ai_row.add(self._ai_model_combo)
        ai_row.add(Box.createHorizontalStrut(8))
        self._ai_verify_btn = JButton("AI Verify: OFF", actionPerformed=self._toggle_ai_verify)
        self._ai_verify_btn.setFont(Font("Consolas", Font.BOLD, 12))
        self._ai_verify_btn.setForeground(Color(150, 0, 0))
        self._ai_verify_btn.setToolTipText("After each IDOR test, ask the AI to double-check whether the finding looks like a real vulnerability.")
        ai_row.add(self._ai_verify_btn)
        top.add(ai_row)

        # --- Row 5: live pool stats ------------------------------------------
        pool_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self._pool_label = JLabel("ID Pool: 0 keys | 0 total IDs | Selected: 0 keys | Manual Overrides: 0 | Active Skills: 0")
        self._pool_label.setFont(Font("Consolas", Font.PLAIN, 11))
        self._pool_label.setForeground(Color(0, 80, 120))
        pool_row.add(self._pool_label)
        top.add(pool_row)

        # --- Row 6: compact mode legend (full text lives in the tooltip) ---
        info = JPanel(FlowLayout(FlowLayout.LEFT))
        info_label = JLabel(u"Pwnfox: red=Attacker, blue=Victim  |  6 testing modes available - hover for details \u2139")
        info_label.setFont(Font("Consolas", Font.PLAIN, 11))
        info_label.setToolTipText(
            "<html>(1) Pwnfox + Keys &nbsp; (2) Manual IDs + Keys &nbsp; (3) Manual IDs<br>"
            "(4) Pool Swap &nbsp; (5) Per-Key Override &nbsp; (6) AI Skills</html>")
        info.add(info_label)
        top.add(info)

        mid = JPanel(BorderLayout())
        mid.setBorder(BorderFactory.createTitledBorder("Manual - Load Request and Analyze"))
        btn_row = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_analyze = JButton("Analyze Loaded Request", actionPerformed=self._analyze_request)
        btn_analyze.setToolTipText("Scan the loaded request for candidate ID fields (regex-based).")
        btn_ai_analyze = JButton("AI Analyze", actionPerformed=self._ai_analyze_request)
        btn_ai_analyze.setToolTipText("Ask the AI to identify candidate ID fields in the loaded request.")
        btn_test = JButton("Test Checked Fields", actionPerformed=self._start_test_thread)
        btn_test.setToolTipText("Run IDOR swap tests on every field checked in the table below.")
        btn_row.add(btn_analyze)
        btn_row.add(btn_ai_analyze)
        btn_row.add(btn_test)
        mid.add(btn_row, BorderLayout.SOUTH)

        fld_cols = ["Test?", "Field Name", "Location", "Current Value"]
        self._fld_model = DefaultTableModel(fld_cols, 0)
        self._fld_table = JTable(self._fld_model)
        self._fld_table.setAutoCreateRowSorter(True)
        mid.add(JScrollPane(self._fld_table), BorderLayout.CENTER)

        bot = JPanel(BorderLayout())
        bot.setBorder(BorderFactory.createTitledBorder(u"Results (Auto + Manual + AI Skills)  \u2014  vulnerable rows are highlighted"))
        res_cols = ["ID", "Key", "Location", "Status", "Length", "Sim%", "Vuln", "Notes"]
        self._res_model = ResultsTableModel()
        for c in res_cols:
            self._res_model.addColumn(c)
        self._res_table = JTable(self._res_model)
        sorter = TableRowSorter(self._res_model)
        from java.util import Comparator
        int_comp = Comparator.naturalOrder()
        sorter.setComparator(0, int_comp)
        sorter.setComparator(4, int_comp)
        sorter.setComparator(5, int_comp)
        self._res_table.setRowSorter(sorter)
        col_count = self._res_model.getColumnCount()
        for col_idx in range(col_count):
            if col_idx == 5:
                self._res_table.getColumnModel().getColumn(col_idx).setCellRenderer(SimRenderer())
            else:
                self._res_table.getColumnModel().getColumn(col_idx).setCellRenderer(VulnRowRenderer())

        btn_view = JButton("View Comparison", actionPerformed=self._view_selected)
        btn_repeater = JButton("Send to Repeater", actionPerformed=self._send_repeater)
        self._stats = JLabel("Tested: 0 | Vulnerable: 0")
        self._stats.setFont(Font("Consolas", Font.BOLD, 12))
        self._stats.setForeground(Color(0, 100, 0))

        bot_btn = JPanel(FlowLayout(FlowLayout.LEFT))
        bot_btn.add(btn_view)
        bot_btn.add(btn_repeater)
        bot_btn.add(Box.createHorizontalStrut(8))
        btn_clear_res = JButton("Clear Results", actionPerformed=self._clear_results)
        bot_btn.add(btn_clear_res)
        bot_btn.add(Box.createHorizontalStrut(20))
        bot_btn.add(self._stats)
        bot.add(bot_btn, BorderLayout.NORTH)
        bot.add(JScrollPane(self._res_table), BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, mid, bot)
        split.setDividerLocation(200)
        self._panel.add(top, BorderLayout.NORTH)
        self._panel.add(split, BorderLayout.CENTER)

    def getTabCaption(self): return "IDOR Tester"
    def getUiComponent(self): return self._panel

    def createMenuItems(self, invocation):
        menu = []
        item = JMenuItem("Send to IDOR Tester", actionPerformed=lambda e, inv=invocation: self._load_from_context(inv))
        menu.append(item)
        item2 = JMenuItem("AI Analyze Request", actionPerformed=lambda e, inv=invocation: self._ai_analyze_from_context(inv))
        menu.append(item2)
        item3 = JMenuItem("Run AI Skills on Request", actionPerformed=lambda e, inv=invocation: self._run_skills_from_context(inv))
        menu.append(item3)
        return menu

    def _load_from_context(self, invocation):
        msgs = invocation.getSelectedMessages()
        if msgs and len(msgs) > 0:
            self._last_message = msgs[0]
            self._callbacks.printOutput("[+] Request loaded from context menu")
            self._analyze_request(None)

    def _run_skills_from_context(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs or len(msgs) == 0:
            return
        if not self._ai_enabled:
            JOptionPane.showMessageDialog(self._panel, "Turn AI Extract ON first!", "Error", JOptionPane.WARNING_MESSAGE)
            return
        self._last_message = msgs[0]
        req_str = self._helpers.bytesToString(msgs[0].getRequest())
        self._callbacks.printOutput("[Skills] Context-menu skill run triggered...")
        t = threading.Thread(target=self._run_ai_skills_thread, args=(req_str, msgs[0]))
        t.setDaemon(True)
        t.start()

    def _toggle_scope(self, event):
        self._scope_check_enabled = not self._scope_check_enabled
        if self._scope_check_enabled:
            self._scope_btn.setText("Scope-Only: ON")
            self._scope_btn.setForeground(Color(0, 150, 0))
            self._callbacks.printOutput("[+] Scope-Only ENABLED.")
        else:
            self._scope_btn.setText("Scope-Only: OFF")
            self._scope_btn.setForeground(Color(150, 0, 0))
            self._callbacks.printOutput("[-] Scope-Only DISABLED.")

    def _toggle_auto_extract(self, event):
        self._auto_extract_enabled = not self._auto_extract_enabled
        if self._auto_extract_enabled:
            self._auto_extract_btn.setText("Auto-Extract IDs: ON")
            self._auto_extract_btn.setForeground(Color(0, 150, 0))
            self._callbacks.printOutput("[+] Auto-Extract ENABLED. Learning key=value from URL + Body with Pwnfox labels...")
        else:
            self._auto_extract_btn.setText("Auto-Extract IDs: OFF")
            self._auto_extract_btn.setForeground(Color(150, 0, 0))
            self._callbacks.printOutput("[-] Auto-Extract DISABLED.")

    def _ai_analyze_from_context(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs or len(msgs) == 0:
            return
        if not self._ai_enabled:
            JOptionPane.showMessageDialog(self._panel, "Turn AI Extract ON first!", "Error", JOptionPane.WARNING_MESSAGE)
            return
        req = msgs[0]
        req_str = self._helpers.bytesToString(req.getRequest())
        self._callbacks.printOutput("[AI] Manual context-menu analyze triggered...")
        t = threading.Thread(target=self._ai_extract_thread, args=(req_str,))
        t.setDaemon(True)
        t.start()

    def _toggle_key_visibility(self, event):
        # JPasswordField.setEchoChar('\0') reveals the plaintext; restoring
        # the bullet char re-masks it. Lets the user double check what they
        # pasted/typed without leaving the key permanently visible on screen.
        if self._ai_key_field.getEchoChar() != 0:
            self._ai_key_field.setEchoChar('\0')
            self._ai_key_show_btn.setText("Hide")
        else:
            self._ai_key_field.setEchoChar(u'\u2022')
            self._ai_key_show_btn.setText("Show")

    def _toggle_html_skip(self, event):
        self._html_skip_issue = not self._html_skip_issue
        if self._html_skip_issue:
            self._html_btn.setText("HTML Skip Issue: ON")
            self._html_btn.setForeground(Color(0, 150, 0))
            self._callbacks.printOutput("[+] HTML Skip Issue ENABLED. HTML responses will not register Burp scan issues.")
        else:
            self._html_btn.setText("HTML Skip Issue: OFF")
            self._html_btn.setForeground(Color(150, 0, 0))
            self._callbacks.printOutput("[-] HTML Skip Issue DISABLED.")

    def _toggle_ai_verify(self, event):
        self._ai_verify_enabled = not self._ai_verify_enabled
        if self._ai_verify_enabled:
            key = self._ai_key_field.getText()
            if key is None or key.strip() == "":
                self._ai_verify_enabled = False
                self._ai_verify_btn.setText("AI Verify: OFF")
                self._ai_verify_btn.setForeground(Color(150, 0, 0))
                JOptionPane.showMessageDialog(self._panel, "Enter API Key first!", "Missing Key", JOptionPane.WARNING_MESSAGE)
                return
            self._ai_verify_btn.setText("AI Verify: ON")
            self._ai_verify_btn.setForeground(Color(0, 150, 0))
            self._callbacks.printOutput("[+] AI Verify ENABLED. Post-test AI analysis will run.")
        else:
            self._ai_verify_btn.setText("AI Verify: OFF")
            self._ai_verify_btn.setForeground(Color(150, 0, 0))
            self._callbacks.printOutput("[-] AI Verify DISABLED.")

    def _toggle_ai(self, event):
        self._ai_enabled = not self._ai_enabled
        if self._ai_enabled:
            key = self._ai_key_field.getText()
            if key is None or key.strip() == "":
                self._ai_enabled = False
                self._ai_btn.setText("AI Extract: OFF")
                self._ai_btn.setForeground(Color(150, 0, 0))
                JOptionPane.showMessageDialog(self._panel, "Enter OpenRouter API Key first!", "Missing Key", JOptionPane.WARNING_MESSAGE)
                return
            self._ai_btn.setText("AI Extract: ON")
            self._ai_btn.setForeground(Color(0, 150, 0))
            self._callbacks.printOutput("[+] AI Extract ENABLED (" + self._ai_provider + " | " + self._ai_model + ")")
        else:
            self._ai_btn.setText("AI Extract: OFF")
            self._ai_btn.setForeground(Color(150, 0, 0))
            self._callbacks.printOutput("[-] AI Extract DISABLED.")

    def _set_ai_provider(self):
        self._ai_provider = str(self._ai_provider_combo.getSelectedItem())
        self._callbacks.printOutput("[AI] Provider set to: " + self._ai_provider)
        self._ai_model_combo.removeAllItems()
        if self._ai_provider == "Groq":
            self._ai_key_label.setText("Groq Key:")
            models = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "llama3-8b-8192", "gemma2-9b-it", "mixtral-8x7b-32768"]
        elif self._ai_provider == "Kimi":
            self._ai_key_label.setText("Kimi Key:")
            models = [
                "moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k",
                "kimi-k1.5", "kimi-k2", "kimi-k2-0715",
                "kimi-k2.5", "kimi-k2.5-202501", "kimi-k2.5-202502",
                "kimi-k2.5-202503", "kimi-k2.5-202504", "kimi-k2.5-202505",
                "kimi-k2.5-202506", "kimi-k2.5-202507", "kimi-k2.5-202508",
                "kimi-k2.5-202509", "kimi-k2.5-202510", "kimi-k2.5-202511",
                "kimi-k2.5-202512", "kimi-k2.5-202601", "kimi-k2.5-202602",
                "kimi-k2.5-202603", "kimi-k2.5-202604", "kimi-k2.5-202605",
                "kimi-k2.5-202606", "kimi-k2.5-202607", "kimi-k2.5-202608",
                "kimi-k3", "kimi-k3-202508", "kimi-k3-202509", "kimi-k3-202510"
            ]
        elif self._ai_provider == "Anthropic":
            self._ai_key_label.setText("Anthropic Key:")
            models = [
                "claude-opus-5", "claude-sonnet-5", "claude-fable-5", "claude-mythos-5",
                "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-opus-4-5-20251101",
                "claude-sonnet-4-6", "claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001",
                "claude-opus-4-1-20250805", "claude-opus-4-20250514", "claude-sonnet-4-20250514",
                "claude-3-7-sonnet-latest", "claude-3-7-sonnet-20250219",
                "claude-3-5-sonnet-latest", "claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20240620",
                "claude-3-5-haiku-latest", "claude-3-5-haiku-20241022",
                "claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"
            ]
        else:
            self._ai_key_label.setText("OpenRouter Key:")
            models = ["openai/gpt-oss-20b:free", "nvidia/nemotron-3-ultra-550b-a55b:free"]
        for m in models:
            self._ai_model_combo.addItem(m)
        self._ai_model = str(self._ai_model_combo.getSelectedItem())

    def _set_ai_model(self):
        self._ai_model = str(self._ai_model_combo.getSelectedItem())
        self._callbacks.printOutput("[AI] Model set to: " + self._ai_model)

    def _test_ai_key(self, event):
        key = self._ai_key_field.getText()
        if key is None or key.strip() == "":
            JOptionPane.showMessageDialog(self._panel, "Enter API Key first!", "Error", JOptionPane.WARNING_MESSAGE)
            return
        self._callbacks.printOutput("[AI] Testing API key...")
        t = threading.Thread(target=self._test_ai_key_thread, args=(key.strip(),))
        t.setDaemon(True)
        t.start()

    def _make_ai_request(self, payload_dict, api_key, timeout=25):
        max_retries = 3
        base_delay = 3
        payload_str = json.dumps(payload_dict)
        if isinstance(payload_str, unicode):
            payload_bytes = payload_str.encode("utf-8")
        else:
            payload_bytes = payload_str

        if self._ai_provider == "Groq":
            endpoint = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                "Authorization": "Bearer " + api_key,
                "Content-Type": "application/json",
                "User-Agent": "IDOR-Tester/1.0"
            }
        elif self._ai_provider == "Anthropic":
            endpoint = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
                "User-Agent": "IDOR-Tester/1.0"
            }
        else:
            endpoint = "https://openrouter.ai/api/v1/chat/completions"
            headers = {
                "Authorization": "Bearer " + api_key,
                "Content-Type": "application/json",
                "User-Agent": "IDOR-Tester/1.0",
                "HTTP-Referer": "https://burpsuite.local",
                "X-Title": "IDOR Tester"
            }

        self._callbacks.printOutput("[AI] Requesting " + endpoint + " with model=" + payload_dict.get("model", "unknown"))

        for attempt in range(max_retries + 1):
            try:
                req = urllib2.Request(endpoint, data=payload_bytes, headers=headers)
                resp = urllib2.urlopen(req, timeout=timeout)
                resp_bytes = resp.read()
                data = json.loads(resp_bytes)
                if self._ai_provider == "Anthropic" and "content" in data:
                    text_parts = []
                    for item in data.get("content", []):
                        if item.get("type") == "text":
                            text_parts.append(item.get("text", ""))
                    if text_parts:
                        data = {
                            "choices": [{"message": {"content": " ".join(text_parts)}}]
                        }
                return data
            except urllib2.HTTPError as e:
                code = e.getcode()
                try:
                    err_body = e.read()
                    err_msg = str(err_body)[:500]
                except Exception as read_err:
                    err_msg = "Could not read error body: " + str(read_err)
                self._callbacks.printOutput("[AI] HTTP Error " + str(code) + " | Body: " + err_msg)
                if code == 429:
                    wait = 10
                    self._callbacks.printOutput("[AI] 429 Too Many Requests. Waiting " + str(wait) + "s before retry " + str(attempt+1) + "/" + str(max_retries))
                    time.sleep(wait)
                    if attempt == max_retries:
                        raise Exception("HTTP " + str(code) + ": " + err_msg)
                elif code == 502:
                    wait = 5
                    self._callbacks.printOutput("[AI] 502 Bad Gateway. Waiting " + str(wait) + "s before retry " + str(attempt+1) + "/" + str(max_retries))
                    time.sleep(wait)
                    if attempt == max_retries:
                        raise Exception("HTTP " + str(code) + ": " + err_msg)
                elif code == 403:
                    self._callbacks.printOutput("[AI] 403 Forbidden - possible causes: blocked model, missing permissions, or TLS/SNI issue.")
                    if self._ai_provider == "Groq":
                        self._callbacks.printOutput("[AI] Groq 403: Check https://console.groq.com/settings/limits to enable the model.")
                        self._callbacks.printOutput("[AI] Also verify your API key has access to model: " + self._ai_model)
                    raise Exception("HTTP 403: " + err_msg)
                else:
                    wait = base_delay * (attempt + 1)
                    self._callbacks.printOutput("[AI] HTTP " + str(code) + ". Waiting " + str(wait) + "s before retry " + str(attempt+1) + "/" + str(max_retries))
                    time.sleep(wait)
                    if attempt == max_retries:
                        raise Exception("HTTP " + str(code) + ": " + err_msg)
            except Exception as e:
                wait = base_delay * (attempt + 1)
                self._callbacks.printOutput("[AI] Request error: " + str(e) + ". Waiting " + str(wait) + "s before retry " + str(attempt+1) + "/" + str(max_retries))
                time.sleep(wait)
                if attempt == max_retries:
                    raise
        return None

    def _test_ai_key_thread(self, api_key):
        try:
            prompt = "Reply with exactly: OK"
            payload = {
                "model": self._ai_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": 10
            }
            data = self._make_ai_request(payload, api_key, timeout=15)
            msg = data["choices"][0]["message"]["content"]
            self._callbacks.printOutput("[AI] API Test OK (" + self._ai_provider + " | model=" + self._ai_model + "): " + str(msg))
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self._panel, "API Key is valid!\nProvider: " + self._ai_provider + "\nModel: " + self._ai_model + "\nResponse: " + str(msg), "Success", JOptionPane.INFORMATION_MESSAGE))
        except Exception as e:
            self._callbacks.printError("[-] API Test failed: " + str(e))
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self._panel, "API Test failed!\n" + str(e), "Error", JOptionPane.ERROR_MESSAGE))

    def _toggle_auto_test(self, event):
        self._auto_test_enabled = not self._auto_test_enabled
        if self._auto_test_enabled:
            has_labeled = self._has_labeled_ids()
            has_manual = bool(self._atk_field.getText().strip() and self._vic_field.getText().strip())
            has_selected = len(self._selected_keys) > 0
            has_pool_multi = self._has_pool_multi_ids()
            has_key_mapping = len(self._key_id_mapping) > 0

            if not has_labeled and not has_manual and not has_pool_multi and not has_key_mapping:
                self._auto_test_enabled = False
                self._auto_test_btn.setText("Auto-Test: OFF")
                self._auto_test_btn.setForeground(Color(150, 0, 0))
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    self._panel,
                    "Auto-Test needs one of the following:\n\n"
                    "Mode 1: Pwnfox Auto-Label + Select Keys\n"
                    "Mode 2: Manual IDs + Select Keys\n"
                    "Mode 3: Manual IDs only (no key selection)\n"
                    "Mode 4: Select Keys + Pool IDs (2+ IDs per key)\n"
                    "Mode 5: Per-Key ID Override in Select Keys",
                    "IDs Required", JOptionPane.ERROR_MESSAGE))
                return

            self._auto_test_btn.setText("Auto-Test: ON")
            self._auto_test_btn.setForeground(Color(0, 150, 0))
            if has_labeled and has_selected:
                self._callbacks.printOutput("[+] Auto-Test: Pwnfox labeled keys + selected keys mode.")
            elif has_manual and has_selected:
                self._callbacks.printOutput("[+] Auto-Test: Manual IDs + selected keys mode.")
            elif has_manual:
                self._callbacks.printOutput("[+] Auto-Test: Manual IDs only mode (any request with attacker ID).")
            elif has_pool_multi and has_selected:
                self._callbacks.printOutput("[+] Auto-Test: Selected keys + Pool IDs mode (swap within pool).")
            elif has_key_mapping and has_selected:
                self._callbacks.printOutput("[+] Auto-Test: Per-Key ID Override mode.")
            self._callbacks.printOutput("[+] Manual ID overrides active: " + str(len(self._key_id_mapping)) + " keys")
            self._processed_urls.clear()
            t = threading.Thread(target=self._scan_proxy_history)
            t.setDaemon(True)
            t.start()
        else:
            self._auto_test_btn.setText("Auto-Test: OFF")
            self._auto_test_btn.setForeground(Color(150, 0, 0))
            self._callbacks.printOutput("[-] Auto-Test DISABLED.")

    def _has_labeled_ids(self):
        with self._lock:
            for key, mapping in self._key_id_mapping.items():
                if mapping.get("attacker") and mapping.get("victim"):
                    return True
            for key, ids in self._id_pool.items():
                has_attacker = False
                has_victim = False
                for id_val, info in ids.items():
                    if info.get("label", "").lower() in ("attacker", "account 1", "acc1", "user1"):
                        has_attacker = True
                    if info.get("label", "").lower() in ("victim", "account 2", "acc2", "user2"):
                        has_victim = True
                if has_attacker and has_victim:
                    return True
        return False

    def _has_pool_multi_ids(self):
        with self._lock:
            for key in self._selected_keys:
                if key in self._id_pool and len(self._id_pool[key]) >= 2:
                    return True
        return False

    def _get_labeled_ids_for_key(self, key):
        with self._lock:
            if key in self._key_id_mapping:
                mapping = self._key_id_mapping[key]
                if mapping.get("attacker") and mapping.get("victim"):
                    return mapping["attacker"], mapping["victim"]
        attacker_id = None
        victim_id = None
        with self._lock:
            if key in self._id_pool:
                for id_val, info in self._id_pool[key].items():
                    lbl = info.get("label", "").lower()
                    if lbl in ("attacker", "account 1", "acc1", "user1"):
                        attacker_id = id_val
                    elif lbl in ("victim", "account 2", "acc2", "user2"):
                        victim_id = id_val
        return attacker_id, victim_id

    def _get_all_keys_with_labels(self):
        result = []
        with self._lock:
            for key, mapping in self._key_id_mapping.items():
                atk = mapping.get("attacker")
                vic = mapping.get("victim")
                if atk and vic:
                    result.append((key, atk, vic))
            manual_keys = {r[0] for r in result}
            for key, ids in self._id_pool.items():
                if key in manual_keys:
                    continue
                has_attacker = False
                has_victim = False
                atk = None
                vic = None
                for id_val, info in ids.items():
                    lbl = info.get("label", "").lower()
                    if lbl in ("attacker", "account 1", "acc1", "user1"):
                        has_attacker = True
                        atk = id_val
                    elif lbl in ("victim", "account 2", "acc2", "user2"):
                        has_victim = True
                        vic = id_val
                if has_attacker and has_victim:
                    result.append((key, atk, vic))
        return result

    def _get_pwnfox_color(self, req_str):
        if not req_str:
            return None
        for line in req_str.split("\r\n"):
            if line.lower().startswith("x-pwnfox-color:"):
                return line.split(":", 1)[1].strip().lower()
        return None

    def _is_key_in_request(self, req_str, key):
        if not key or not req_str:
            return False
        patterns = [
            key + "=",
            '"' + key + '"',
            "'" + key + "'",
            "&" + key + "=",
            "?" + key + "=",
            "/" + key + "/",
            "\"" + key + "\":"
        ]
        for pat in patterns:
            if pat in req_str:
                return True
        if key.endswith("_id"):
            base = key[:-3]
            plural_patterns = [
                "/" + base + "s/",
                "/" + base + "/",
                "/" + base + "es/",
            ]
            for pat in plural_patterns:
                if pat in req_str:
                    return True
        return False

    def _is_id_in_url_or_body(self, req_str, matched_id):
        """
        Checks whether `matched_id` appears as a whole token in the request
        line / body - NOT as a plain substring.

        Plain substring search (`matched_id in text`) is unreliable for
        short/numeric ids: an attacker id of "42" would "match" inside
        "page=142", "limit=420", a timestamp, or any other unrelated number
        that merely contains "42" - silently firing IDOR tests against
        requests that have nothing to do with that id. The lookaround here
        requires the match not be glued to another alnum/underscore
        character on either side, so it only matches the id as a standalone
        token (e.g. in "id=42", "/objects/42", "\"user_id\":42").
        """
        if not req_str or not matched_id:
            return False
        parts = req_str.split("\r\n\r\n", 1)
        headers = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        header_lines = headers.split("\r\n")
        request_line = header_lines[0] if header_lines else ""
        pattern = r"(?<![0-9A-Za-z_])" + re.escape(matched_id) + r"(?![0-9A-Za-z_])"
        if re.search(pattern, request_line):
            return True
        if re.search(pattern, body):
            return True
        return False

    def _is_html_response(self, response_bytes):
        if not response_bytes:
            return False
        resp_str = self._helpers.bytesToString(response_bytes)
        lower = resp_str.lower()
        if "content-type: text/html" in lower:
            return True
        body = self._get_body_from_str(resp_str)
        if body.strip().startswith("<"):
            return True
        return False

    def _is_pool_id_in_request(self, req_str, key):
        if not key or not req_str:
            return False
        with self._lock:
            if key not in self._id_pool:
                return False
            pool_ids = list(self._id_pool[key])
        # Same word-boundary reasoning as _is_id_in_url_or_body: a plain
        # substring check would let a short pool id (e.g. "5") match inside
        # any unrelated longer number in the request.
        for id_val in pool_ids:
            pattern = r"(?<![0-9A-Za-z_])" + re.escape(id_val) + r"(?![0-9A-Za-z_])"
            if re.search(pattern, req_str):
                return True
        return False

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # toolFlag == 4 is TOOL_PROXY: only ever look at traffic that went
        # through Burp's Proxy (i.e. Proxy > HTTP History), never Repeater/
        # Scanner/Intruder/etc.
        if toolFlag != 4:
            return
        if not messageIsRequest:
            return

        req_bytes = messageInfo.getRequest()
        if req_bytes is None:
            return
        req_str = self._helpers.bytesToString(req_bytes)

        req_info = self._helpers.analyzeRequest(messageInfo)
        url = req_info.getUrl()
        method = req_info.getMethod()

        # BUG FIX: the scope check used to only gate auto-TEST below, not
        # id EXTRACTION above it. That meant "Scope-Only: ON" did nothing
        # for extraction - the id pool silently filled up from every single
        # request that happened to pass through the proxy port (ads,
        # trackers, unrelated tabs/domains, background app traffic), not
        # just the target you're actually testing. Moving the scope check
        # up so it gates BOTH extraction and testing the same way.
        if self._scope_check_enabled and not self._callbacks.isInScope(url):
            return

        if self._auto_extract_enabled:
            self._extract_ids_from_request(messageInfo, req_str)

        if not self._auto_test_enabled:
            return

        if method == "OPTIONS":
            return

        pwnfox_color = self._get_pwnfox_color(req_str)
        manual_atk = self._atk_field.getText().strip()
        manual_vic = self._vic_field.getText().strip()
        tested_any = False

        if pwnfox_color == "red":
            for key in self._selected_keys:
                atk_id, vic_id = self._get_labeled_ids_for_key(key)
                if atk_id and vic_id and self._is_id_in_url_or_body(req_str, atk_id):
                    self._queue_auto_test(messageInfo, req_str, key, atk_id, vic_id)
                    tested_any = True
            if not tested_any and manual_atk and manual_vic:
                if self._is_id_in_url_or_body(req_str, manual_atk):
                    self._queue_auto_test(messageInfo, req_str, "manual", manual_atk, manual_vic)
                    tested_any = True
        elif pwnfox_color == "blue":
            for key in self._selected_keys:
                atk_id, vic_id = self._get_labeled_ids_for_key(key)
                if atk_id and vic_id and self._is_id_in_url_or_body(req_str, vic_id):
                    self._queue_auto_test(messageInfo, req_str, key, vic_id, atk_id)
                    tested_any = True
            if not tested_any and manual_atk and manual_vic:
                if self._is_id_in_url_or_body(req_str, manual_vic):
                    self._queue_auto_test(messageInfo, req_str, "manual", manual_vic, manual_atk)
                    tested_any = True
        else:
            # Default (no Pwnfox tag) mode: this is the attacker's own
            # traffic passing through the proxy, so the ONLY meaningful
            # test is replacing the ATTACKER's id with the VICTIM's id
            # (can the attacker's session pull the victim's data?).
            # We must NEVER swap victim_id -> attacker_id here - that
            # would just be "attacker accesses their own resource using
            # their own id", which proves nothing and used to fire
            # (incorrectly) whenever a victim id merely appeared in an
            # otherwise normal attacker request.
            labeled_keys = self._get_all_keys_with_labels()
            for key, atk_id, vic_id in labeled_keys:
                if key in self._selected_keys:
                    if self._is_id_in_url_or_body(req_str, atk_id):
                        self._queue_auto_test(messageInfo, req_str, key, atk_id, vic_id)
                        tested_any = True

            if not tested_any and manual_atk and manual_vic and len(self._selected_keys) > 0:
                for key in self._selected_keys:
                    is_labeled = False
                    for lk, latk, lvic in labeled_keys:
                        if lk == key:
                            is_labeled = True
                            break
                    if is_labeled:
                        continue
                    key_in_req = self._is_key_in_request(req_str, key) or self._is_pool_id_in_request(req_str, key)
                    if key_in_req and self._is_id_in_url_or_body(req_str, manual_atk):
                        self._queue_auto_test(messageInfo, req_str, key, manual_atk, manual_vic)
                        tested_any = True
                        break

            if not tested_any and manual_atk and manual_vic and len(self._selected_keys) == 0:
                if self._is_id_in_url_or_body(req_str, manual_atk):
                    self._queue_auto_test(messageInfo, req_str, "manual", manual_atk, manual_vic)
                    tested_any = True

            if not tested_any and len(self._selected_keys) > 0:
                for key in self._selected_keys:
                    is_labeled = False
                    for lk, latk, lvic in labeled_keys:
                        if lk == key:
                            is_labeled = True
                            break
                    if is_labeled:
                        continue
                    key_in_req = self._is_key_in_request(req_str, key) or self._is_pool_id_in_request(req_str, key)
                    if not key_in_req:
                        continue
                    pool_ids = []
                    with self._lock:
                        if key in self._id_pool:
                            pool_ids = list(self._id_pool[key].keys())
                    if len(pool_ids) < 2:
                        continue
                    for i, pid in enumerate(pool_ids):
                        if self._is_id_in_url_or_body(req_str, pid):
                            other_idx = 1 if i == 0 else 0
                            other_id = pool_ids[other_idx]
                            self._queue_auto_test(messageInfo, req_str, key, pid, other_id)
                            tested_any = True
                            break

    def _extract_ids_from_request(self, messageInfo, req_str):
        req_info = self._helpers.analyzeRequest(messageInfo)
        url_str = req_info.getUrl().toString()

        pwnfox_color = self._get_pwnfox_color(req_str)
        auto_label = ""
        if pwnfox_color == "red":
            auto_label = "Attacker"
        elif pwnfox_color == "blue":
            auto_label = "Victim"

        if "?" in url_str:
            query = url_str.split("?", 1)[1]
            for pair in re.split(r'[&;]', query):
                if "=" in pair:
                    key, val = pair.split("=", 1)
                    key = urllib.unquote(key.strip())
                    val = urllib.unquote(val.strip())
                    if self._is_valid_id_key(key) and self._looks_like_id(val, key):
                        self._add_to_pool(key, val, "Regex-URL", auto_label)
            path = url_str.split("?", 1)[0]
            path_parts = path.split("/")
            for i, part in enumerate(path_parts):
                if self._looks_like_id(part):
                    key = "id"
                    if i > 0 and path_parts[i-1]:
                        key = path_parts[i-1].lower().rstrip("s") + "_id"
                    if self._is_valid_id_key(key):
                        self._add_to_pool(key, part, "Regex-URL-Path", auto_label)
            # Explicit key=value / key:value pairs embedded inside a path
            # segment (matrix params like ";id=555;status=paid", or inline
            # "user_id=42" segments). split/pair instead of guessing the key
            # from the previous segment - the key name is already explicit.
            for key, val in self._extract_path_keyvalue_pairs(path_parts):
                if self._looks_like_id(val, key):
                    self._add_to_pool(key, val, "Regex-URL-PathKV", auto_label)

        for p in req_info.getParameters():
            ptype = p.getType()
            if ptype in (IParameter.PARAM_BODY, IParameter.PARAM_URL):
                key = p.getName()
                val = p.getValue()
                decoded_val = urllib.unquote(val)
                if self._is_valid_id_key(key) and self._looks_like_id(decoded_val, key):
                    loc = "Regex-Body" if ptype == IParameter.PARAM_BODY else "Regex-URL"
                    self._add_to_pool(key, decoded_val, loc, auto_label)
                if decoded_val.strip().startswith("{") or decoded_val.strip().startswith("["):
                    try:
                        jdata = json.loads(decoded_val)
                        self._extract_json_ids(jdata, key, auto_label)
                    except:
                        pass

        # JSON "key": "value" (string values) - existing behavior.
        json_pattern = re.compile(r'"([a-zA-Z_][a-zA-Z0-9_\-]*)"\s*:\s*"([^"]+)"')
        for m in json_pattern.finditer(req_str):
            key, val = m.group(1), m.group(2)
            if self._is_valid_id_key(key) and self._looks_like_id(val, key):
                self._add_to_pool(key, val, "Regex-JSON-Raw", auto_label)

        # JSON "key": 12345 (bare numeric values, no quotes). This is the
        # most common shape for ids in JSON APIs and the string-only pattern
        # above misses it entirely - "user_id":88214 previously produced no
        # match at all, silently dropping the single most likely id field.
        json_num_pattern = re.compile(r'"([a-zA-Z_][a-zA-Z0-9_\-]*)"\s*:\s*(-?\d{3,20})(?=\s*[,}\]])')
        for m in json_num_pattern.finditer(req_str):
            key, val = m.group(1), m.group(2)
            if self._is_valid_id_key(key) and self._looks_like_id(val, key):
                self._add_to_pool(key, val, "Regex-JSON-Raw", auto_label)

        json_pattern2 = re.compile(r"'([a-zA-Z_][a-zA-Z0-9_\-]*)'\s*:\s*'([^']+)'")
        for m in json_pattern2.finditer(req_str):
            key, val = m.group(1), m.group(2)
            if self._is_valid_id_key(key) and self._looks_like_id(val, key):
                self._add_to_pool(key, val, "Regex-JSON-Raw", auto_label)

        # form_pattern key charset previously only allowed [a-zA-Z0-9_], so
        # keys like "order-id=555" (hyphen), "user.id=42" (dot), or PHP-style
        # "items[0][id]=99" (brackets) were silently skipped. Broadened to
        # include -, ., [ and ] in the key.
        form_pattern = re.compile(r"(?:^|[&?;\s])([a-zA-Z_][a-zA-Z0-9_\-\.\[\]]*)=([^&;\s]+)")
        for m in form_pattern.finditer(req_str):
            key = m.group(1)
            raw_val = m.group(2)
            val = raw_val
            for _ in range(3):
                decoded = urllib.unquote(val)
                if decoded == val:
                    break
                val = decoded
            if self._is_valid_id_key(key) and self._looks_like_id(val, key):
                self._add_to_pool(key, val, "Regex-Body-Raw", auto_label)
            if key.lower() in ("signed_body", "signed_payload", "ig_sig_key_version"):
                if "." in val:
                    parts = val.split(".", 1)
                    sig = parts[0]
                    payload = parts[1]
                    try:
                        payload_decoded = urllib.unquote(payload)
                        for _ in range(2):
                            d = urllib.unquote(payload_decoded)
                            if d == payload_decoded:
                                break
                            payload_decoded = d
                        if payload_decoded.strip().startswith("{"):
                            jdata = json.loads(payload_decoded)
                            self._extract_json_ids(jdata, key, auto_label)
                            if self._is_valid_id_key(key) and self._looks_like_id(sig, key):
                                self._add_to_pool(key + "_sig", sig, "Regex-Body-Signed", auto_label)
                    except:
                        pass
            if val.strip().startswith("{") or val.strip().startswith("["):
                try:
                    jdata = json.loads(val)
                    self._extract_json_ids(jdata, key, auto_label)
                except:
                    pass

        # XML text-node style: <account_id>7788</account_id>. Namespaced tags
        # (<ns:id>...</ns:id>) are matched too via the [\w:.\-]* tag charset.
        xml_pattern = re.compile(r"<([a-zA-Z_][\w:.\-]*)>([^<]+)</\1>")
        for m in xml_pattern.finditer(req_str):
            key, val = m.group(1), m.group(2)
            if self._is_valid_id_key(key) and self._looks_like_id(val, key):
                self._add_to_pool(key, val, "Regex-XML", auto_label)

        # XML/HTML attribute style: <user id="4021" ...>. The tag-body
        # pattern above only ever matched <tag>value</tag> and silently
        # missed ids carried as attributes, which is just as common
        # (SOAP/XML-RPC payloads, HTML forms).
        xml_attr_pattern = re.compile(r'<[a-zA-Z_][\w:.\-]*[^>]*?\s([a-zA-Z_][\w\-]*)\s*=\s*"([^"]+)"')
        for m in xml_attr_pattern.finditer(req_str):
            key, val = m.group(1), m.group(2)
            if self._is_valid_id_key(key) and self._looks_like_id(val, key):
                self._add_to_pool(key, val, "Regex-XML-Attr", auto_label)

        auth_pattern = re.compile(r"[Bb]earer\s+([a-zA-Z0-9_-]+)")
        for m in auth_pattern.finditer(req_str):
            val = m.group(1)
            if self._looks_like_id(val):
                self._add_to_pool("authorization_token", val, "Regex-Header", auto_label)

        body = self._get_body_from_str(req_str)
        if body.strip().startswith("{") or body.strip().startswith("["):
            try:
                jdata = json.loads(body)
                self._extract_json_ids(jdata, "", auto_label)
            except:
                pass

    def _ai_extract_thread(self, req_str):
        try:
            key = self._ai_key_field.getText()
            if key is None:
                return
            api_key = key.strip()
            if not api_key:
                return
            self._callbacks.printOutput("[AI] Calling " + self._ai_provider + " (model=" + self._ai_model + ")...")

            headers = self._get_headers_from_str(req_str)
            body = self._get_body_from_str(req_str)
            url_line = headers[0] if headers else ""

            prompt = (
                "You are an IDOR security scanner. Analyze this HTTP request and extract EVERY key=value pair "
                "that looks like an ID, UUID, token, or object reference. "
                "ONLY extract from the URL query string and request body. "
                "DO NOT extract from headers, cookies, or authorization tokens. "
                "Return ONLY a valid JSON array. No markdown. No explanations. "
                'Format: [{\"key\":\"param_name\",\"value\":\"12345\",\"location\":\"URL\" or "Body"}]\n\n'
                "URL: " + url_line[:500] + "\n"
                "BODY: " + body[:3000]
            )

            self._callbacks.printOutput("[AI] Prompt length: " + str(len(prompt)))
            payload = {
                "model": self._ai_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": 4000
            }
            data = self._make_ai_request(payload, api_key, timeout=25)
            content = None
            if "choices" in data and len(data["choices"]) > 0:
                choice = data["choices"][0]
                if "message" in choice and "content" in choice["message"]:
                    content = choice["message"]["content"]
            if content is None or content == "":
                self._callbacks.printOutput("[-] AI returned empty response")
                return
            self._callbacks.printOutput("[AI] Raw: " + str(content)[:500])
            result = self._parse_ai_json(content)
            if result is None:
                self._callbacks.printOutput("[-] AI response not parseable")
                return
            if not isinstance(result, list):
                self._callbacks.printOutput("[-] AI response is not a list")
                return
            added = 0
            for item in result:
                if isinstance(item, dict):
                    k = str(item.get("key", "")).strip()
                    v = str(item.get("value", "")).strip()
                    loc = str(item.get("location", "AI")).strip().lower()
                    if loc in ("header", "headers", "cookie", "cookies", "auth", "authorization"):
                        self._callbacks.printOutput("[AI] Skipped header item: " + k)
                        continue
                    if k and v and len(v) >= 2:
                        ai_source = "AI-" + loc.upper() if loc else "AI"
                        self._add_to_pool_direct(k, v, ai_source, "")
                        added += 1
                        self._callbacks.printOutput("[AI] + " + k + "=" + v[:30] + " [" + ai_source + "]")
            self._callbacks.printOutput("[AI] Done. Added " + str(added) + " IDs to pool.")
        except Exception as e:
            self._callbacks.printError("[-] AI extract error: " + str(e))

    def _fix_truncated_json(self, text):
        text = text.strip()
        last_bracket = text.rfind("}")
        if last_bracket > 0:
            remainder = text[last_bracket+1:].strip()
            if remainder and not remainder.startswith("]"):
                fixed = text[:last_bracket+1] + "]"
                try:
                    json.loads(fixed)
                    return fixed
                except:
                    pass
        if text.startswith("[") and not text.endswith("]"):
            fixed = text + "]"
            try:
                json.loads(fixed)
                return fixed
            except:
                pass
        if text.startswith("{") and not text.endswith("}"):
            fixed = text + "}"
            try:
                json.loads(fixed)
                return fixed
            except:
                pass
        return text

    def _parse_ai_json(self, text):
        text = str(text).strip()
        self._callbacks.printOutput("[AI] Parse input length: " + str(len(text)))
        try:
            result = json.loads(text)
            self._callbacks.printOutput("[AI] Parse: direct json.loads OK")
            return result
        except Exception as e:
            self._callbacks.printOutput("[AI] Parse: direct json.loads failed: " + str(e)[:100])
        try:
            fixed = self._fix_truncated_json(text)
            if fixed != text:
                result = json.loads(fixed)
                self._callbacks.printOutput("[AI] Parse: truncated JSON fix OK")
                return result
        except Exception as e:
            self._callbacks.printOutput("[AI] Parse: truncated fix failed: " + str(e)[:100])
        try:
            s = text.find("[")
            e = text.rfind("]")
            if s >= 0 and e > s:
                subset = text[s:e+1]
                result = json.loads(subset)
                self._callbacks.printOutput("[AI] Parse: bracket extraction OK")
                return result
            else:
                self._callbacks.printOutput("[AI] Parse: no brackets found")
        except Exception as e:
            self._callbacks.printOutput("[AI] Parse: bracket extraction failed: " + str(e)[:100])
        try:
            fixed = text.replace("'", '"').replace(",]", "]").replace(",}", "}")
            fixed = re.sub(r",(\s*[}\]])", r"\1", fixed)
            s = fixed.find("[")
            e = fixed.rfind("]")
            if s >= 0 and e > s:
                result = json.loads(fixed[s:e+1])
                self._callbacks.printOutput("[AI] Parse: fixed bracket extraction OK")
                return result
        except Exception as e:
            self._callbacks.printOutput("[AI] Parse: fixed extraction failed: " + str(e)[:100])
        try:
            import re as _re
            code_block = _re.search(r'```(?:json)?\s*(\[.*?\])\s*```', text, _re.DOTALL)
            if code_block:
                result = json.loads(code_block.group(1))
                self._callbacks.printOutput("[AI] Parse: code block extraction OK")
                return result
        except Exception as e:
            self._callbacks.printOutput("[AI] Parse: code block extraction failed: " + str(e)[:100])
        self._callbacks.printOutput("[AI] Parse: all methods failed")
        return None

    def _is_valid_id_key(self, key):
        key_lower = key.lower()
        skip = {"timestamp", "datetime", "date", "time", "version", "build",
                "epoch", "page", "limit", "offset", "count", "total", "size",
                "max", "min", "sleep", "wait", "retry", "timeout", "per_page",
                "sort", "order", "direction", "search", "query", "q", "term",
                "format", "callback", "_", "t", "v", "csrf", "token", "auth"}
        return key_lower not in skip

    def _looks_like_id(self, val, key_hint=None):
        """
        Heuristically decides whether `val` looks like a resource id.

        Bare short numbers (e.g. "4337") were previously ALWAYS rejected
        because the numeric pattern required a minimum of 5 digits
        regardless of context - so something like {"custom_lineup_id":
        "4337"} was silently dropped even though the field name makes it
        obvious this is an id. When the caller can tell us the field name
        (key_hint) and it clearly reads as an identifier ("id", "..._id",
        "..._pk", "..._key"), we trust that signal and accept much shorter
        numeric values (down to 2 digits). Without a key hint we keep the
        stricter 5-digit floor, since a bare 3-4 digit number with no name
        context at all (e.g. a page count, a quantity) is too likely to be
        unrelated noise.
        """
        if not val:
            return False
        min_digits = 5
        if key_hint:
            kl = str(key_hint).lower()
            if kl == "id" or kl.endswith("id") or re.search(r"(^|_)(id|pk|key)(_|$)", kl):
                min_digits = 2
        if re.match(r"^\d{" + str(min_digits) + ",20}$", val):
            return True
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*_\d{" + str(min_digits) + ",20}$", val):
            return True
        if len(val) < 3:
            return False
        if re.match(r"^\d{5,20}_\d{5,20}$", val):
            return True
        if re.match(r"^[0-9a-f]{8,64}_[0-9a-f]{8,64}$", val, re.IGNORECASE):
            return True
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", val, re.IGNORECASE):
            return True
        if re.match(r"^[0-9a-f]{24}$", val, re.IGNORECASE):
            return True
        if re.match(r"^[0-9a-f]{32,64}$", val, re.IGNORECASE):
            return True
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*_[0-9a-f]{8,64}$", val, re.IGNORECASE):
            return True
        return False

    def _extract_json_ids(self, obj, prefix, auto_label=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = prefix + "." + k if prefix else k
                if isinstance(v, (dict, list)):
                    self._extract_json_ids(v, full_key, auto_label)
                elif isinstance(v, (int, long)):
                    sv = str(v)
                    if self._is_valid_id_key(k) and self._looks_like_id(sv, k):
                        self._add_to_pool(full_key, sv, "Regex-Body(JSON-Num)", auto_label)
                else:
                    sv = str(v)
                    if self._is_valid_id_key(k) and self._looks_like_id(sv, k):
                        self._add_to_pool(full_key, sv, "Regex-Body(JSON)", auto_label)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                full_key = prefix + "[" + str(i) + "]"
                if isinstance(v, (dict, list)):
                    self._extract_json_ids(v, full_key, auto_label)
                elif isinstance(v, (int, long)):
                    sv = str(v)
                    parent_key = prefix if prefix else "item"
                    if self._is_valid_id_key(parent_key) and self._looks_like_id(sv, parent_key):
                        self._add_to_pool(parent_key, sv, "Regex-Body(JSON-Num)", auto_label)
                else:
                    sv = str(v)
                    parent_key = prefix if prefix else "item"
                    if self._is_valid_id_key(parent_key) and self._looks_like_id(sv, parent_key):
                        self._add_to_pool(parent_key, sv, "Regex-Body(JSON)", auto_label)

    def _add_to_pool(self, key, id_value, source, label=""):
        with self._lock:
            if key not in self._id_pool:
                self._id_pool[key] = {}
            if id_value not in self._id_pool[key]:
                self._id_pool[key][id_value] = {"label": label, "source": source}
            elif label and not self._id_pool[key][id_value].get("label"):
                self._id_pool[key][id_value]["label"] = label
            self._update_pool_label()

    def _add_to_pool_direct(self, key, id_value, source, label=""):
        with self._lock:
            if key not in self._id_pool:
                self._id_pool[key] = {}
            if id_value not in self._id_pool[key]:
                self._id_pool[key][id_value] = {"label": label, "source": source}
            elif label and not self._id_pool[key][id_value].get("label"):
                self._id_pool[key][id_value]["label"] = label
            self._update_pool_label()

    def _update_pool_label(self):
        total_keys = len(self._id_pool)
        total_ids = sum(len(v) for v in self._id_pool.values())
        selected_count = len(self._selected_keys)
        manual_count = len(self._key_id_mapping)
        active_skills = sum(1 for s in self._skills if s.get("enabled", False))
        def run():
            self._pool_label.setText("ID Pool: " + str(total_keys) + " keys | " + str(total_ids) + " total IDs | Selected: " + str(selected_count) + " keys | Manual Overrides: " + str(manual_count) + " | Active Skills: " + str(active_skills))
        SwingUtilities.invokeLater(run)

    def _view_id_pool(self, event):
        dialog = JDialog()
        dialog.setTitle("ID Pool - Label IDs by Account")
        dialog.setSize(800, 500)
        panel = JPanel(BorderLayout())

        search_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        search_field = JTextField(25)
        search_field.setToolTipText("Search by Key, ID Value, Label, Source or Method")
        search_panel.add(JLabel("Search:"))
        search_panel.add(search_field)
        btn_clear_search = JButton("Clear", actionPerformed=lambda e: search_field.setText(""))
        search_panel.add(btn_clear_search)
        panel.add(search_panel, BorderLayout.NORTH)

        cols = ["Key", "ID Value", "Label", "Source", "Method"]
        model = DefaultTableModel(cols, 0)
        table = JTable(model)
        sorter = TableRowSorter(model)
        table.setRowSorter(sorter)

        with self._lock:
            for key, ids in sorted(self._id_pool.items()):
                for id_val, info in sorted(ids.items()):
                    src = info.get("source", "")
                    if src == "AI" or src.startswith("AI-"):
                        method = "AI"
                    else:
                        method = "Regex"
                    model.addRow([key, id_val, info.get("label", ""), src, method])

        class SearchKeyListener(KeyAdapter):
            def keyReleased(self, e):
                txt = search_field.getText().strip()
                if txt:
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + txt))
                else:
                    sorter.setRowFilter(None)
        search_field.addKeyListener(SearchKeyListener())

        panel.add(JScrollPane(table), BorderLayout.CENTER)

        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        label_options = ["", "Attacker", "Victim", "Account 1", "Account 2", "Account 3"]
        self._label_combo = JComboBox(label_options)
        btn_panel.add(JLabel("Label:"))
        btn_panel.add(self._label_combo)

        btn_set = JButton("Set Label", actionPerformed=lambda e: self._set_label_on_selected(table, model))
        btn_clear = JButton("Clear Label", actionPerformed=lambda e: self._clear_label_on_selected(table, model))
        btn_refresh = JButton("Refresh", actionPerformed=lambda e: self._refresh_pool_table(model, sorter))
        btn_panel.add(btn_set)
        btn_panel.add(btn_clear)
        btn_panel.add(btn_refresh)

        panel.add(btn_panel, BorderLayout.SOUTH)

        dialog.add(panel)
        dialog.setVisible(True)

    def _refresh_pool_table(self, model, sorter=None):
        model.setRowCount(0)
        with self._lock:
            for key, ids in sorted(self._id_pool.items()):
                for id_val, info in sorted(ids.items()):
                    src = info.get("source", "")
                    if src == "AI" or src.startswith("AI-"):
                        method = "AI"
                    else:
                        method = "Regex"
                    model.addRow([key, id_val, info.get("label", ""), src, method])
        if sorter:
            sorter.setRowFilter(None)

    def _set_label_on_selected(self, table, model):
        row = table.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(table, "Select a row first!", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        model_row = table.convertRowIndexToModel(row)
        key = str(model.getValueAt(model_row, 0))
        id_val = str(model.getValueAt(model_row, 1))
        label = str(self._label_combo.getSelectedItem())
        with self._lock:
            if key in self._id_pool and id_val in self._id_pool[key]:
                self._id_pool[key][id_val]["label"] = label
                model.setValueAt(label, model_row, 2)
                self._callbacks.printOutput("[POOL] " + key + "=" + id_val + " labeled as '" + label + "'")
        self._update_pool_label()
        self._update_id_fields_from_labels()

    def _clear_label_on_selected(self, table, model):
        row = table.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(table, "Select a row first!", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        model_row = table.convertRowIndexToModel(row)
        key = str(model.getValueAt(model_row, 0))
        id_val = str(model.getValueAt(model_row, 1))
        with self._lock:
            if key in self._id_pool and id_val in self._id_pool[key]:
                self._id_pool[key][id_val]["label"] = ""
                model.setValueAt("", model_row, 2)
        self._update_pool_label()
        self._update_id_fields_from_labels()

    def _update_id_fields_from_labels(self):
        with self._lock:
            for key, ids in self._id_pool.items():
                for id_val, info in ids.items():
                    lbl = info.get("label", "").lower()
                    if lbl in ("attacker", "account 1", "acc1", "user1"):
                        self._atk_field.setText(id_val)
                        self._attacker_id = id_val
                    elif lbl in ("victim", "account 2", "acc2", "user2"):
                        self._vic_field.setText(id_val)
                        self._victim_id = id_val

    def _set_id_from_pool(self, which):
        dialog = JDialog()
        dialog.setTitle("Select ID from Pool")
        dialog.setSize(600, 400)
        panel = JPanel(BorderLayout())

        cols = ["Key", "ID Value", "Label", "Source", "Method"]
        model = DefaultTableModel(cols, 0)
        table = JTable(model)
        with self._lock:
            for key, ids in sorted(self._id_pool.items()):
                for id_val, info in sorted(ids.items()):
                    src = info.get("source", "")
                    method = "AI" if src == "AI" else "Regex"
                    model.addRow([key, id_val, info.get("label", ""), src, method])

        panel.add(JScrollPane(table), BorderLayout.CENTER)

        def do_set(e):
            row = table.getSelectedRow()
            if row < 0:
                return
            id_val = str(model.getValueAt(row, 1))
            if which == "attacker":
                self._atk_field.setText(id_val)
            else:
                self._vic_field.setText(id_val)
            dialog.dispose()

        btn = JButton("Use Selected", actionPerformed=do_set)
        btn_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        btn_panel.add(btn)
        panel.add(btn_panel, BorderLayout.SOUTH)

        dialog.add(panel)
        dialog.setVisible(True)

    def _select_keys_dialog(self, event):
        dialog = JDialog()
        dialog.setTitle("Select Keys to Test")
        dialog.setSize(900, 700)
        panel = JPanel(BorderLayout())

        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

        add_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        add_field = JTextField(20)
        add_btn = JButton("Add Key", actionPerformed=lambda e: self._add_key_manual(add_field, dialog))
        add_panel.add(JLabel("Key Name:"))
        add_panel.add(add_field)
        add_panel.add(add_btn)
        add_panel.add(JLabel("  (Use if pool is empty)"))
        top_panel.add(add_panel)

        search_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        search_field = JTextField(20)
        search_field.setToolTipText("Search by Key, Attacker ID, Victim ID, Mode or Found By")
        search_panel.add(JLabel("Search:"))
        search_panel.add(search_field)
        btn_clear_search = JButton("Clear", actionPerformed=lambda e: search_field.setText(""))
        search_panel.add(btn_clear_search)
        top_panel.add(search_panel)

        info = JLabel("Check keys to test. 'Auto' = labeled IDs swap. 'Manual' = uses Attacker/Victim fields above. 'Per-Key' = select IDs below.")
        info_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        info_panel.add(info)
        top_panel.add(info_panel)

        panel.add(top_panel, BorderLayout.NORTH)

        cols = ["Test?", "Key", "Count", "Attacker ID", "Victim ID", "Mode", "Found By"]
        model = CheckBoxTableModel()
        for c in cols:
            model.addColumn(c)
        table = JTable(model)
        sorter = TableRowSorter(model)
        table.setRowSorter(sorter)

        with self._lock:
            for key, ids in sorted(self._id_pool.items()):
                count = len(ids)
                atk = ""
                vic = ""
                if key in self._key_id_mapping:
                    atk = self._key_id_mapping[key].get("attacker", "")
                    vic = self._key_id_mapping[key].get("victim", "")
                if not atk or not vic:
                    for id_val, info in ids.items():
                        lbl = info.get("label", "").lower()
                        if lbl in ("attacker", "account 1", "acc1", "user1"):
                            atk = id_val
                        elif lbl in ("victim", "account 2", "acc2", "user2"):
                            vic = id_val
                if atk and vic:
                    if key in self._key_id_mapping:
                        mode = "Per-Key Manual"
                    else:
                        mode = "Auto (labeled)"
                else:
                    mode = "Manual IDs"
                found_by = "Regex"
                for id_val, info in ids.items():
                    src = info.get("source", "")
                    if src == "AI" or src.startswith("AI-"):
                        found_by = "AI"
                        break
                    elif src.startswith("Regex-"):
                        found_by = "Regex"
                is_selected = key in self._selected_keys
                model.addRow([Boolean(is_selected), key, str(count), atk, vic, mode, found_by])

        class SearchKeyAdapter(KeyAdapter):
            def keyReleased(self, e):
                txt = search_field.getText().strip()
                if txt:
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + txt))
                else:
                    sorter.setRowFilter(None)
        search_field.addKeyListener(SearchKeyAdapter())

        panel.add(JScrollPane(table), BorderLayout.CENTER)

        id_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        id_panel.setBorder(BorderFactory.createTitledBorder("Per-Key ID Override (Attacker/Victim dropdowns show only labeled IDs for this key)"))
        atk_combo = JComboBox()
        atk_combo.setPreferredSize(Dimension(220, 25))
        vic_combo = JComboBox()
        vic_combo.setPreferredSize(Dimension(220, 25))
        id_panel.add(JLabel("Attacker ID:"))
        id_panel.add(atk_combo)
        id_panel.add(Box.createHorizontalStrut(10))
        id_panel.add(JLabel("Victim ID:"))
        id_panel.add(vic_combo)

        def populate_combos():
            row = table.getSelectedRow()
            if row < 0:
                return
            model_row = table.convertRowIndexToModel(row)
            key = str(model.getValueAt(model_row, 1))
            atk_combo.removeAllItems()
            vic_combo.removeAllItems()
            atk_combo.addItem("")
            vic_combo.addItem("")
            with self._lock:
                if key in self._id_pool:
                    for id_val, info in sorted(self._id_pool[key].items()):
                        lbl = info.get("label", "").lower()
                        if lbl in ("attacker", "account 1", "acc1", "user1"):
                            atk_combo.addItem(id_val)
                        elif lbl in ("victim", "account 2", "acc2", "user2"):
                            vic_combo.addItem(id_val)
                if key in self._key_id_mapping:
                    m = self._key_id_mapping[key]
                    if m.get("attacker"):
                        atk_combo.setSelectedItem(m["attacker"])
                    if m.get("victim"):
                        vic_combo.setSelectedItem(m["victim"])

        def do_set_ids():
            row = table.getSelectedRow()
            if row < 0:
                JOptionPane.showMessageDialog(dialog, "Select a key row first!", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            model_row = table.convertRowIndexToModel(row)
            key = str(model.getValueAt(model_row, 1))
            atk = str(atk_combo.getSelectedItem())
            vic = str(vic_combo.getSelectedItem())
            if not atk or not vic:
                JOptionPane.showMessageDialog(dialog, "Select both Attacker and Victim IDs!", "Info", JOptionPane.WARNING_MESSAGE)
                return
            with self._lock:
                self._key_id_mapping[key] = {"attacker": atk, "victim": vic}
            model.setValueAt(atk, model_row, 3)
            model.setValueAt(vic, model_row, 4)
            model.setValueAt("Per-Key Manual", model_row, 5)
            self._callbacks.printOutput("[KEYS] Manual override set for '" + key + "': Attacker=" + atk + ", Victim=" + vic)
            self._update_pool_label()

        def do_clear_ids():
            row = table.getSelectedRow()
            if row < 0:
                JOptionPane.showMessageDialog(dialog, "Select a key row first!", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            model_row = table.convertRowIndexToModel(row)
            key = str(model.getValueAt(model_row, 1))
            with self._lock:
                if key in self._key_id_mapping:
                    del self._key_id_mapping[key]
            atk = ""
            vic = ""
            with self._lock:
                if key in self._id_pool:
                    for id_val, info in self._id_pool[key].items():
                        lbl = info.get("label", "").lower()
                        if lbl in ("attacker", "account 1", "acc1", "user1"):
                            atk = id_val
                        elif lbl in ("victim", "account 2", "acc2", "user2"):
                            vic = id_val
            model.setValueAt(atk, model_row, 3)
            model.setValueAt(vic, model_row, 4)
            if atk and vic:
                model.setValueAt("Auto (labeled)", model_row, 5)
            else:
                model.setValueAt("Manual IDs", model_row, 5)
            self._callbacks.printOutput("[KEYS] Cleared manual override for '" + key + "'")
            self._update_pool_label()
            populate_combos()

        btn_load = JButton("Load Key IDs", actionPerformed=lambda e: populate_combos())
        btn_set = JButton("Set IDs for Key", actionPerformed=lambda e: do_set_ids())
        btn_clear = JButton("Clear Manual IDs", actionPerformed=lambda e: do_clear_ids())
        id_panel.add(Box.createHorizontalStrut(10))
        id_panel.add(btn_load)
        id_panel.add(btn_set)
        id_panel.add(btn_clear)

        south = JPanel(BorderLayout())
        south.add(id_panel, BorderLayout.NORTH)
        btn_ok = JButton("Save Selection", actionPerformed=lambda e: self._save_key_selection(table, model, dialog))
        btn_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        btn_panel.add(btn_ok)
        south.add(btn_panel, BorderLayout.SOUTH)
        panel.add(south, BorderLayout.SOUTH)

        dialog.add(panel)
        dialog.setVisible(True)

    def _add_key_manual(self, text_field, dialog):
        key = text_field.getText().strip()
        if not key:
            return
        with self._lock:
            if key not in self._id_pool:
                self._id_pool[key] = {}
                self._callbacks.printOutput("[+] Manual key added to pool: " + key)
            self._update_pool_label()
        dialog.dispose()
        self._select_keys_dialog(None)

    def _save_key_selection(self, table, model, dialog):
        self._selected_keys.clear()
        for i in range(model.getRowCount()):
            checked = model.getValueAt(i, 0)
            is_checked = False
            if checked is not None:
                if isinstance(checked, Boolean):
                    is_checked = checked.booleanValue()
                else:
                    is_checked = bool(checked)
            if is_checked:
                key = str(model.getValueAt(i, 1))
                self._selected_keys.add(key)
        self._callbacks.printOutput("[+] Selected keys: " + str(self._selected_keys))
        self._callbacks.printOutput("[+] Manual ID overrides: " + str(self._key_id_mapping))
        self._update_pool_label()
        dialog.dispose()

    def _queue_auto_test(self, messageInfo, req_str, key, matched_id, replacement_id):
        req_info = self._helpers.analyzeRequest(messageInfo)
        url = req_info.getUrl().toString()
        method = req_info.getMethod()
        self._callbacks.printOutput("[AUTO] Captured: " + method + " " + url[:60] + " [Key=" + key + "]")
        t = threading.Thread(target=self._auto_test_request, args=(messageInfo, req_str, key, matched_id, replacement_id))
        t.setDaemon(True)
        t.start()

    def _scan_proxy_history(self):
        try:
            self._callbacks.printOutput("[HISTORY] Scanning proxy history...")
            history = self._callbacks.getProxyHistory()
            if not history:
                self._callbacks.printOutput("[HISTORY] No proxy history found.")
                return
            self._callbacks.printOutput("[HISTORY] Total items: " + str(len(history)))
            scanned = 0
            queued = 0
            for msg in history:
                try:
                    req_bytes = msg.getRequest()
                    if req_bytes is None:
                        continue
                    req_str = self._helpers.bytesToString(req_bytes)
                    req_info = self._helpers.analyzeRequest(msg)
                    url = req_info.getUrl().toString()
                    method = req_info.getMethod()

                    if not self._auto_test_enabled:
                        break

                    if method == "OPTIONS":
                        continue

                    scanned += 1
                    if self._scope_check_enabled and not self._callbacks.isInScope(req_info.getUrl()):
                        continue

                    if self._auto_extract_enabled:
                        self._extract_ids_from_request(msg, req_str)

                    pwnfox_color = self._get_pwnfox_color(req_str)
                    manual_atk = self._atk_field.getText().strip()
                    manual_vic = self._vic_field.getText().strip()
                    tested = False

                    if pwnfox_color == "red":
                        for key in self._selected_keys:
                            atk_id, vic_id = self._get_labeled_ids_for_key(key)
                            if atk_id and vic_id and self._is_id_in_url_or_body(req_str, atk_id):
                                dedup_key = method + "|" + url + "|" + key + "|" + atk_id + "|" + vic_id
                                with self._lock:
                                    if dedup_key in self._processed_urls:
                                        continue
                                    self._processed_urls.add(dedup_key)
                                self._callbacks.printOutput("[HISTORY] Queued (Pwnfox red): " + method + " " + url[:60] + " [Key=" + key + "]")
                                t = threading.Thread(target=self._auto_test_request, args=(msg, req_str, key, atk_id, vic_id))
                                t.setDaemon(True)
                                t.start()
                                queued += 1
                                tested = True
                                break
                        if not tested and manual_atk and manual_vic and self._is_id_in_url_or_body(req_str, manual_atk):
                            dedup_key = method + "|" + url + "|manual|" + manual_atk + "|" + manual_vic
                            with self._lock:
                                if dedup_key in self._processed_urls:
                                    continue
                                self._processed_urls.add(dedup_key)
                            self._callbacks.printOutput("[HISTORY] Queued (Pwnfox red manual): " + method + " " + url[:60])
                            t = threading.Thread(target=self._auto_test_request, args=(msg, req_str, "manual", manual_atk, manual_vic))
                            t.setDaemon(True)
                            t.start()
                            queued += 1
                            tested = True
                    elif pwnfox_color == "blue":
                        for key in self._selected_keys:
                            atk_id, vic_id = self._get_labeled_ids_for_key(key)
                            if atk_id and vic_id and self._is_id_in_url_or_body(req_str, vic_id):
                                dedup_key = method + "|" + url + "|" + key + "|" + vic_id + "|" + atk_id
                                with self._lock:
                                    if dedup_key in self._processed_urls:
                                        continue
                                    self._processed_urls.add(dedup_key)
                                self._callbacks.printOutput("[HISTORY] Queued (Pwnfox blue): " + method + " " + url[:60] + " [Key=" + key + "]")
                                t = threading.Thread(target=self._auto_test_request, args=(msg, req_str, key, vic_id, atk_id))
                                t.setDaemon(True)
                                t.start()
                                queued += 1
                                tested = True
                                break
                        if not tested and manual_atk and manual_vic and self._is_id_in_url_or_body(req_str, manual_vic):
                            dedup_key = method + "|" + url + "|manual|" + manual_vic + "|" + manual_atk
                            with self._lock:
                                if dedup_key in self._processed_urls:
                                    continue
                                self._processed_urls.add(dedup_key)
                            self._callbacks.printOutput("[HISTORY] Queued (Pwnfox blue manual): " + method + " " + url[:60])
                            t = threading.Thread(target=self._auto_test_request, args=(msg, req_str, "manual", manual_vic, manual_atk))
                            t.setDaemon(True)
                            t.start()
                            queued += 1
                            tested = True
                    else:
                        labeled_keys = self._get_all_keys_with_labels()
                        for key, atk_id, vic_id in labeled_keys:
                            if key in self._selected_keys:
                                if self._is_id_in_url_or_body(req_str, atk_id):
                                    dedup_key = method + "|" + url + "|" + key + "|" + atk_id + "|" + vic_id
                                    with self._lock:
                                        if dedup_key in self._processed_urls:
                                            continue
                                        self._processed_urls.add(dedup_key)
                                    self._queue_auto_test(msg, req_str, key, atk_id, vic_id)
                                    tested = True

                        if not tested and manual_atk and manual_vic and len(self._selected_keys) > 0:
                            for key in self._selected_keys:
                                is_labeled = False
                                for lk, latk, lvic in labeled_keys:
                                    if lk == key:
                                        is_labeled = True
                                        break
                                if is_labeled:
                                    continue
                                key_in_req = self._is_key_in_request(req_str, key) or self._is_pool_id_in_request(req_str, key)
                                if key_in_req and self._is_id_in_url_or_body(req_str, manual_atk):
                                    dedup_key = method + "|" + url + "|" + key + "|" + manual_atk + "|" + manual_vic
                                    with self._lock:
                                        if dedup_key in self._processed_urls:
                                            continue
                                        self._processed_urls.add(dedup_key)
                                    self._callbacks.printOutput("[HISTORY] Queued (manual): " + method + " " + url[:60] + " [Key=" + key + "]")
                                    t = threading.Thread(target=self._auto_test_request, args=(msg, req_str, key, manual_atk, manual_vic))
                                    t.setDaemon(True)
                                    t.start()
                                    queued += 1
                                    tested = True
                                    break

                        if not tested and manual_atk and manual_vic and len(self._selected_keys) == 0:
                            if self._is_id_in_url_or_body(req_str, manual_atk):
                                dedup_key = method + "|" + url + "|manual|" + manual_atk
                                with self._lock:
                                    if dedup_key in self._processed_urls:
                                        continue
                                    self._processed_urls.add(dedup_key)
                                self._callbacks.printOutput("[HISTORY] Queued (manual): " + method + " " + url[:60])
                                t = threading.Thread(target=self._auto_test_request, args=(msg, req_str, "manual", manual_atk, manual_vic))
                                t.setDaemon(True)
                                t.start()
                                queued += 1
                                tested = True

                        if not tested and len(self._selected_keys) > 0:
                            for key in self._selected_keys:
                                is_labeled = False
                                for lk, latk, lvic in labeled_keys:
                                    if lk == key:
                                        is_labeled = True
                                        break
                                if is_labeled:
                                    continue
                                key_in_req = self._is_key_in_request(req_str, key) or self._is_pool_id_in_request(req_str, key)
                                if not key_in_req:
                                    continue
                                pool_ids = []
                                with self._lock:
                                    if key in self._id_pool:
                                        pool_ids = list(self._id_pool[key].keys())
                                if len(pool_ids) < 2:
                                    continue
                                for i, pid in enumerate(pool_ids):
                                    if self._is_id_in_url_or_body(req_str, pid):
                                        other_idx = 1 if i == 0 else 0
                                        other_id = pool_ids[other_idx]
                                        dedup_key = method + "|" + url + "|" + key + "|" + pid + "|" + other_id
                                        with self._lock:
                                            if dedup_key in self._processed_urls:
                                                continue
                                            self._processed_urls.add(dedup_key)
                                        self._callbacks.printOutput("[HISTORY] Queued (pool): " + method + " " + url[:60] + " [Key=" + key + "]")
                                        t = threading.Thread(target=self._auto_test_request, args=(msg, req_str, key, pid, other_id))
                                        t.setDaemon(True)
                                        t.start()
                                        queued += 1
                                        tested = True
                                        break

                    if scanned % 50 == 0:
                        threading.Event().wait(0.1)
                except Exception as e:
                    self._callbacks.printError("[-] History scan item error: " + str(e))

            self._callbacks.printOutput("[HISTORY] Scan complete. Scanned: " + str(scanned) + " | Queued: " + str(queued))
        except Exception as e:
            self._callbacks.printError("[-] History scan error: " + str(e))

    def _auto_test_request(self, messageInfo, req_str, key, matched_id, replacement_id):
        try:
            req_info = self._helpers.analyzeRequest(messageInfo)
            if req_info.getMethod() == "OPTIONS":
                return
            service = messageInfo.getHttpService()
            original_bytes = messageInfo.getRequest()
            parts = req_str.split("\r\n\r\n", 1)
            headers_part = parts[0]
            body_part = parts[1] if len(parts) > 1 else ""
            header_lines = headers_part.split("\r\n")
            request_line = header_lines[0]
            other_headers = "\r\n".join(header_lines[1:]) if len(header_lines) > 1 else ""
            new_request_line = request_line.replace(matched_id, replacement_id)
            new_body = body_part.replace(matched_id, replacement_id)
            new_headers_part = new_request_line + ("\r\n" + other_headers if other_headers else "")
            new_req_str = new_headers_part + ("\r\n\r\n" + new_body if body_part else "")
            if new_req_str == req_str:
                return
            modified_bytes = self._helpers.stringToBytes(new_req_str)

            self._callbacks.printOutput("[AUTO] Baseline...")
            baseline_resp = self._callbacks.makeHttpRequest(service, original_bytes)
            baseline_bytes = baseline_resp.getResponse() if baseline_resp else None
            baseline_body = ""
            baseline_status = "Err"
            if baseline_bytes:
                bi = self._helpers.analyzeResponse(baseline_bytes)
                baseline_status = str(bi.getStatusCode())
                bo = bi.getBodyOffset()
                if bo < len(baseline_bytes):
                    baseline_body = self._helpers.bytesToString(baseline_bytes[bo:])

            self._callbacks.printOutput("[AUTO] Modified (key=" + key + ")...")
            test_resp = self._callbacks.makeHttpRequest(service, modified_bytes)
            test_bytes = test_resp.getResponse() if test_resp else None
            test_body = ""
            test_status = "Err"
            test_len = 0
            if test_bytes:
                ti = self._helpers.analyzeResponse(test_bytes)
                test_status = str(ti.getStatusCode())
                test_len = len(test_bytes)
                to = ti.getBodyOffset()
                if to < len(test_bytes):
                    test_body = self._helpers.bytesToString(test_bytes[to:])

            similarity, analysis = self._compare_responses(baseline_bytes, baseline_body, test_bytes, test_body)

            has_deny = self._check_deny_keywords(test_body, test_status)
            is_error_json = self._check_error_json(test_body)

            is_vuln = False
            notes = ""
            test_body_len = len(test_body)

            if test_status == "200" and test_body_len > 0 and not has_deny and not is_error_json:
                if self._is_confident_value_match(replacement_id, test_body):
                    is_vuln = True
                    notes = "AUTO-CONFIRMED: Swapped ID found in response body!"
                elif baseline_status == test_status and similarity >= 85:
                    is_vuln = True
                    notes = "AUTO-HIGH: Similar valid response (Sim=" + str(similarity) + "%) - verify manually"
                elif baseline_status == test_status and similarity >= 50:
                    notes = "AUTO-MEDIUM: Partial match (Sim=" + str(similarity) + "%) - verify manually"
                else:
                    notes = "AUTO-LOW: Different response (Sim=" + str(similarity) + "%)"
            elif has_deny:
                notes = "AUTO-Blocked: Permission denied detected (Sim=" + str(similarity) + "%)"
            elif is_error_json:
                notes = "AUTO-Blocked: Error JSON returned (Sim=" + str(similarity) + "%)"
            elif test_status in ("403", "401"):
                notes = "AUTO-Blocked: Auth required (" + test_status + ")"
            elif test_status == "404":
                notes = "AUTO-Blocked: Not found (" + test_status + ")"
            elif test_status.startswith("5"):
                notes = "AUTO-Error: Server error (" + test_status + ")"
            elif test_status == "200" and test_body_len == 0:
                notes = "AUTO-Empty: 200 OK but empty body"
            else:
                notes = "AUTO-Other: " + test_status + " (Sim=" + str(similarity) + "%)"
            notes += " | " + analysis

            if self._ai_verify_enabled:
                ai_verdict = self._ai_verify_result(baseline_body, test_body, baseline_status, test_status, key, matched_id, replacement_id)
                notes += " | " + ai_verdict

            with self._lock:
                self._test_count += 1
                idx = self._test_count
                if is_vuln:
                    self._vuln_count += 1
                self._results.append({
                    "idx": idx, "field": key + "=" + matched_id[:30], "location": "Auto-Captured",
                    "status": test_status, "length": test_len,
                    "similarity": similarity, "vuln": is_vuln, "notes": notes,
                    "original": original_bytes, "modified": modified_bytes,
                    "baseline_response": baseline_bytes, "response": test_bytes,
                    "service": service
                })
            self._log_result(idx, key + "=" + matched_id[:30], "Auto-Captured", test_status, test_len, similarity, is_vuln, notes)
            self._update_stats_label()

            if is_vuln:
                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                is_html = self._is_html_response(test_bytes)
                if self._html_skip_issue and is_html:
                    self._callbacks.printOutput("[AUTO] HTML response detected. Skipping Burp issue registration (toggle is ON).")
                else:
                    self._register_issue(
                        service, url, key, matched_id, replacement_id,
                        original_bytes, modified_bytes, baseline_bytes, test_bytes, notes
                    )
                self._callbacks.printOutput("[AUTO] *** VULNERABLE: " + str(url) + " [Key=" + key + "] ***")

        except Exception as e:
            self._callbacks.printError("[-] Auto-test error: " + str(e))

    def _ai_verify_result(self, baseline_body, test_body, baseline_status, test_status, key, matched_id, replacement_id):
        try:
            key_text = self._ai_key_field.getText()
            if not key_text or not key_text.strip():
                return "AI-Verify: No API key"
            api_key = key_text.strip()

            baseline_snip = str(baseline_body)[:2000] if baseline_body else "[No baseline body]"
            test_snip = str(test_body)[:2000] if test_body else "[No test body]"

            parts = [
                "You are an expert security analyst reviewing an IDOR test.",
                "A request was sent with key ", str(key), " where ID ", str(matched_id),
                " was swapped with ", str(replacement_id), ".",
                " Baseline response status: ", str(baseline_status),
                " Test response status: ", str(test_status), " ",
                "BASELINE RESPONSE BODY (original ID): ", baseline_snip,
                " TEST RESPONSE BODY (swapped ID): ", test_snip,
                " Analyze carefully: Does the test response indicate a VALID IDOR vulnerability?",
                " A valid IDOR means the server returned unauthorized data from another user/account after the ID swap.",
                " Look for: different data, sensitive info leakage, successful access to another user's resources.",
                " Ignore: generic error pages, permission denied messages, 401/403 responses, empty bodies.",
                " Reply with exactly one word first, then explanation:",
                " VULNERABLE - if the swap clearly exposed another user's data",
                " NOT_VULNERABLE - if the response shows access was properly blocked or no leak occurred",
                " UNCERTAIN - if unclear and needs manual review",
                " Format: VERDICT | Brief explanation (max 1 sentence)"
            ]
            prompt = "".join(parts)

            payload = {
                "model": self._ai_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 200
            }
            data = self._make_ai_request(payload, api_key, timeout=20)
            content = None
            if "choices" in data and len(data["choices"]) > 0:
                choice = data["choices"][0]
                if "message" in choice and "content" in choice["message"]:
                    content = choice["message"]["content"]
            if not content:
                return "AI-Verify: Empty response"
            content = str(content).strip()
            self._callbacks.printOutput("[AI-Verify] Raw: " + content[:200])
            up = content.upper()
            if "VULNERABLE" in up and "NOT" not in up.split("VULNERABLE")[0].split()[-1:]:
                return "AI-Verify: VULNERABLE | " + content
            elif "NOT_VULNERABLE" in up or "NOT VULNERABLE" in up:
                return "AI-Verify: NOT_VULNERABLE | " + content
            elif "UNCERTAIN" in up:
                return "AI-Verify: UNCERTAIN | " + content
            else:
                return "AI-Verify: " + content[:100]
        except Exception as e:
            self._callbacks.printError("[-] AI verify error: " + str(e))
            return "AI-Verify: Error (" + str(e)[:50] + ")"

    def _check_deny_keywords(self, body, status_code=None):
        """
        Returns True only when we have strong evidence the response is an
        authorization denial, not just a response that happens to contain a
        common word like "invalid" or "fail" somewhere in unrelated content
        (e.g. a validation message inside an otherwise successfully leaked
        object). Strong keywords are decisive on their own; weak keywords
        only count if the HTTP status also looks like a denial (4xx).
        """
        if not body:
            return False
        body_lower = body.lower()

        for kw in self._deny_keywords:
            if kw in body_lower:
                return True

        if status_code and str(status_code).startswith("4"):
            for kw in self._weak_deny_keywords:
                if kw in body_lower:
                    return True

        return False

    def _is_confident_value_match(self, injected_value, body):
        """
        Returns True only if `injected_value` appearing inside `body` is a
        reliable signal of an IDOR leak, not a coincidence.

        Plain substring search (`value in body`) is unreliable for short or
        generic values: "0", "-1", "1", "true" etc. can legitimately appear
        anywhere in a normal JSON/HTML response (timestamps, counters,
        unrelated fields) and would otherwise be marked "CONFIRMED" wrongly.
        We require a minimum length and exclude a small denylist of generic
        tokens so this check only fires for values specific enough to be
        meaningful (e.g. a swapped victim ID, a mutated UUID segment).
        """
        if not injected_value or not body:
            return False
        val = str(injected_value).strip()
        if len(val) < 6:
            return False
        if val.lower() in ("true", "false", "null", "none", "undefined"):
            return False
        return val in body

    def _check_error_json(self, body):
        if not body or not body.strip().startswith("{"):
            return False
        try:
            j = json.loads(body)
            if isinstance(j, dict):
                if j.get("success") is False:
                    return True
                if j.get("error") or j.get("errors") or j.get("message"):
                    msg = str(j.get("error", "")) + " " + str(j.get("errors", "")) + " " + str(j.get("message", ""))
                    if any(kw in msg.lower() for kw in self._deny_keywords):
                        return True
                # NOTE: a generic "code" field is NOT a reliable error signal -
                # it's just as likely to be a promo/zip/verification/product
                # code that happens to start with "4" or "5" (e.g. "code":
                # "451022") as an HTTP-status-shaped field. That false
                # positive used to suppress genuine IDOR findings. Only
                # trust field names that are unambiguously HTTP-status-like,
                # and only when the value is an actual HTTP error status.
                http_error_codes = (400, 401, 402, 403, 404, 405, 406, 408,
                                     409, 410, 422, 429, 500, 501, 502, 503, 504)
                for status_key in ("status_code", "statusCode", "http_code", "httpCode",
                                    "errorCode", "error_code"):
                    val = j.get(status_key)
                    if val is None:
                        continue
                    try:
                        if int(val) in http_error_codes:
                            return True
                    except (ValueError, TypeError):
                        pass
        except:
            pass
        return False

    def _register_issue(self, http_service, url, field_name, original_id, swapped_id,
                       original_req, modified_req, baseline_resp, test_resp, notes=""):
        # Confidence/severity should reflect how sure the heuristic actually
        # was, not be hard-coded "Certain"/"High" for every finding. A
        # similarity-based "verify manually" guess is a real hit less often
        # than an exact injected-value match, and reporting both as
        # "Certain" misleads whoever reads the Burp issue list/report.
        notes_upper = str(notes).upper()
        if "CONFIRMED" in notes_upper:
            severity, confidence = "High", "Certain"
        elif "HIGH" in notes_upper:
            severity, confidence = "High", "Firm"
        else:
            severity, confidence = "Medium", "Tentative"
        try:
            detail = (
                "<b>Key:</b> " + str(field_name) + "<br>"
                "<b>Original ID:</b> " + str(original_id) + "<br>"
                "<b>Swapped ID:</b> " + str(swapped_id) + "<br>"
                "<b>Confidence basis:</b> " + str(notes) + "<br><br>"
                "<b>Potential IDOR Vulnerability.</b><br><br>"
                "Swapping '" + str(original_id) + "' with '" + str(swapped_id) +
                "' in key '" + str(field_name) + "' returned valid data."
            )
            msg1 = CustomHttpRequestResponse(http_service, original_req, baseline_resp,
                comment="[IDOR] Original Request + Baseline Response")
            msg2 = CustomHttpRequestResponse(http_service, modified_req, test_resp,
                comment="[IDOR] Modified Request + Test Response (ID Swapped)")
            issue = IDORScanIssue(http_service, url,
                "IDOR: " + str(field_name) + " on " + str(url.getPath()),
                detail, severity, confidence, [msg1, msg2])
            self._callbacks.addScanIssue(issue)
        except Exception as e:
            self._callbacks.printError("[-] Issue reg error: " + str(e))

    def _ai_analyze_request(self, event):
        if not self._last_message:
            JOptionPane.showMessageDialog(self._panel, "Load a request first!", "Error", JOptionPane.WARNING_MESSAGE)
            return
        if not self._ai_enabled:
            JOptionPane.showMessageDialog(self._panel, "Turn AI Extract ON first!", "Error", JOptionPane.WARNING_MESSAGE)
            return
        req_str = self._helpers.bytesToString(self._last_message.getRequest())
        self._callbacks.printOutput("[AI] Manual analyze triggered...")
        t = threading.Thread(target=self._ai_extract_thread, args=(req_str,))
        t.setDaemon(True)
        t.start()

    def _extract_path_keyvalue_pairs(self, path_parts):
        """
        Extract explicit key=value (or key:value) pairs embedded INSIDE a
        single URL path segment, e.g.:
            /api/orders;id=555;status=paid/items      (matrix parameters)
            /api/orders,id=555,region=eu/items         (comma-separated)
            /api/resource/user_id=42/details            (inline pair)

        This is different from the positional logic above (`for i, part in
        enumerate(path_parts): ...`), which only handles BARE id segments
        like /users/123 and has to GUESS the key name from the previous
        segment. Here the key name is already explicit in the segment text,
        so instead of guessing we just split each segment on the pair
        separator (';' or ',') and then split each token on '=' or ':' to
        get a real (key, value) pair - much more reliable than regex
        guessing for this shape of URL.
        """
        pairs = []
        for part in path_parts:
            if not part or ("=" not in part and ":" not in part):
                continue
            # Matrix params use ';' between pairs; some APIs use ','.
            for token in re.split(r"[;,]", part):
                token = token.strip()
                if not token:
                    continue
                if "=" in token:
                    key, _, value = token.partition("=")
                elif ":" in token and not token.lower().startswith(("http:", "https:")):
                    key, _, value = token.partition(":")
                else:
                    continue
                key = key.strip()
                value = value.strip()
                if not key or not value:
                    continue
                if not self._is_valid_id_key(key):
                    continue
                pairs.append((key, value))
        return pairs

    def _analyze_request(self, event):
        self._attacker_id = self._atk_field.getText().strip()
        self._victim_id = self._vic_field.getText().strip()
        if not self._last_message:
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self._panel, "Load a request first (right-click > Send to IDOR Tester)",
                "Error", JOptionPane.WARNING_MESSAGE))
            return
        req_info = self._helpers.analyzeRequest(self._last_message)
        req_str = self._helpers.bytesToString(self._last_message.getRequest())
        url = req_info.getUrl().toString()
        self._callbacks.printOutput("[DEBUG] Analyzing: " + url)
        self._fields = []
        self._fld_model.setRowCount(0)

        pwnfox_color = self._get_pwnfox_color(req_str)
        auto_label = ""
        if pwnfox_color == "red":
            auto_label = "Attacker"
        elif pwnfox_color == "blue":
            auto_label = "Victim"

        url_params = req_info.getParameters()
        for p in url_params:
            pval = p.getValue()
            pname = p.getName()
            is_candidate = self._is_valid_id_key(pname) and (
                self._looks_like_id(pval, pname) or (self._victim_id and pval == self._victim_id)
                or (self._attacker_id and pval == self._attacker_id)
            )
            if p.getType() == IParameter.PARAM_URL:
                if is_candidate:
                    self._add_field(pname, "URL", pval)
                    self._add_to_pool_direct(pname, pval, "Regex-URL", auto_label)
            elif p.getType() == IParameter.PARAM_BODY:
                if is_candidate:
                    self._add_field(pname, "Body (Form)", pval)
                    self._add_to_pool_direct(pname, pval, "Regex-Body", auto_label)

        url_str_full = req_info.getUrl().toString()
        path = url_str_full.split("?", 1)[0]
        path_parts = path.split("/")
        for i, part in enumerate(path_parts):
            # NOTE: unlike JSON/query-param keys, `key` here is synthetically
            # built by appending "_id" to whatever the previous path segment
            # happens to be (e.g. .../page/42/... -> "page_id"). That means
            # it would ALWAYS end in "id" and trivially satisfy the relaxed
            # key_hint threshold in _looks_like_id for every numeric path
            # segment, defeating its purpose. So we deliberately do NOT pass
            # a key hint here and keep the stricter no-context threshold.
            if self._looks_like_id(part):
                key = "id"
                if i > 0 and path_parts[i-1]:
                    seg = path_parts[i-1].lower()
                    key = seg.rstrip("s") + "_id"
                    alias = seg + "_id"
                    if alias != key and self._is_valid_id_key(alias):
                        self._add_field(alias, "URL (Path)", part)
                        self._add_to_pool_direct(alias, part, "Regex-URL-Path", auto_label)
                if self._is_valid_id_key(key):
                    self._add_field(key, "URL (Path)", part)
                    self._add_to_pool_direct(key, part, "Regex-URL-Path", auto_label)

        # Explicit key=value pairs embedded inside a path segment (matrix
        # params, inline "key=value" segments). Uses split/pair instead of
        # guessing the key from position - more accurate whenever the key
        # name is actually present in the URL.
        for key, value in self._extract_path_keyvalue_pairs(path_parts):
            if self._looks_like_id(value, key) or (self._victim_id and value == self._victim_id) \
                    or (self._attacker_id and value == self._attacker_id):
                self._add_field(key, "URL (Path-KV)", value)
                self._add_to_pool_direct(key, value, "Regex-URL-PathKV", auto_label)

        body = self._get_body_from_str(req_str)
        if body.strip().startswith("{") or body.strip().startswith("["):
            try:
                jdata = json.loads(body)
                self._extract_json_fields(jdata, "Body (JSON)", auto_label)
            except:
                pass

        self._callbacks.printOutput("[+] Found " + str(len(self._fields)) + " candidate fields")
        self._callbacks.printOutput("[+] Pool updated with " + str(len(self._id_pool)) + " keys from analysis")

        if self._ai_enabled:
            t = threading.Thread(target=self._ai_extract_thread, args=(req_str,))
            t.setDaemon(True)
            t.start()

    def _get_body_from_str(self, req_str):
        idx = req_str.find("\r\n\r\n")
        if idx >= 0:
            return req_str[idx + 4:]
        return ""

    def _get_headers_from_str(self, req_str):
        idx = req_str.find("\r\n\r\n")
        if idx >= 0:
            return req_str[:idx].split("\r\n")
        return req_str.split("\r\n")

    def _add_field(self, name, location, value):
        self._fields.append({"name": name, "location": location, "value": value})
        self._fld_model.addRow([True, name, location, value])

    def _extract_json_fields(self, obj, prefix, auto_label="", path=""):
        """
        Walks a parsed JSON body to find candidate id fields for the manual
        "Analyze Loaded Request" table.

        Previously this only kept a value if it exactly contained the
        already-configured victim_id/attacker_id ("self._victim_id in sv or
        self._attacker_id in sv"). Two problems with that:
        1. If those fields were still empty (e.g. you haven't set them yet,
           which is a very normal order of operations - analyze first,
           decide ids after) NOTHING was ever extracted from JSON bodies.
        2. Every other id-shaped field (order_id, product_id, parent_id...)
           that wasn't already known to be the victim/attacker id was
           silently skipped, even though it's exactly the kind of field
           this table is meant to surface.
        Now it uses the same generic "does this look like an id" check
        (_looks_like_id) used everywhere else in the tool, while still
        keeping an exact match against victim/attacker id as a fallback for
        ids that don't fit the generic shape (e.g. short custom ids).
        """
        if isinstance(obj, dict):
            for k, v in obj.items():
                full = path + "." + k if path else k
                if isinstance(v, (dict, list)):
                    self._extract_json_fields(v, prefix, auto_label, full)
                else:
                    sv = str(v)
                    if self._is_valid_id_key(k) and (
                        self._looks_like_id(sv, k)
                        or (self._victim_id and sv == self._victim_id)
                        or (self._attacker_id and sv == self._attacker_id)
                    ):
                        self._add_field(full, prefix, sv)
                        self._add_to_pool_direct(full, sv, "Regex-" + prefix, auto_label)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                full = path + "[" + str(i) + "]"
                if isinstance(v, (dict, list)):
                    self._extract_json_fields(v, prefix, auto_label, full)
                else:
                    sv = str(v)
                    if self._looks_like_id(sv) or (self._victim_id and sv == self._victim_id) \
                            or (self._attacker_id and sv == self._attacker_id):
                        self._add_field(full, prefix, sv)
                        self._add_to_pool_direct(full, sv, "Regex-" + prefix, auto_label)

    def _start_test_thread(self, event):
        t = threading.Thread(target=self._test_selected)
        t.setDaemon(True)
        t.start()

    def _test_selected(self):
        if not self._last_message:
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self._panel, "Analyze a request first!", "Error", JOptionPane.WARNING_MESSAGE))
            return
        self._attacker_id = self._atk_field.getText().strip()
        self._victim_id = self._vic_field.getText().strip()
        if not self._attacker_id or not self._victim_id:
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self._panel, "Set both IDs first!", "Error", JOptionPane.ERROR_MESSAGE))
            return
        service = self._last_message.getHttpService()
        original_bytes = self._last_message.getRequest()
        original_str = self._helpers.bytesToString(original_bytes)

        pwnfox_color = self._get_pwnfox_color(original_str)
        if pwnfox_color == "red":
            direction = "atk_to_vic"
            self._callbacks.printOutput("[MANUAL] Pwnfox red detected. Only swapping Attacker->Victim.")
        elif pwnfox_color == "blue":
            direction = "vic_to_atk"
            self._callbacks.printOutput("[MANUAL] Pwnfox blue detected. Only swapping Victim->Attacker.")
        else:
            direction = "auto"
            self._callbacks.printOutput("[MANUAL] No Pwnfox header. Bidirectional swap enabled.")

        baseline_resp = self._callbacks.makeHttpRequest(service, original_bytes)
        baseline_bytes = baseline_resp.getResponse() if baseline_resp else None
        baseline_body = ""
        baseline_status = "Err"
        if baseline_bytes:
            bi = self._helpers.analyzeResponse(baseline_bytes)
            baseline_status = str(bi.getStatusCode())
            bo = bi.getBodyOffset()
            if bo < len(baseline_bytes):
                baseline_body = self._helpers.bytesToString(baseline_bytes[bo:])
        tested_any = False
        for i in range(self._fld_model.getRowCount()):
            try:
                if not self._fld_model.getValueAt(i, 0):
                    continue
                field_name = str(self._fld_model.getValueAt(i, 1))
                location = str(self._fld_model.getValueAt(i, 2))
                tested_any = True
                modified = self._build_modified_request(original_str, field_name, location, direction)
                if modified is None:
                    continue
                mod_str = self._helpers.bytesToString(modified)
                if mod_str == original_str:
                    continue
                test_resp = self._callbacks.makeHttpRequest(service, modified)
                test_bytes = test_resp.getResponse() if test_resp else None
                test_body = ""
                test_status = "Err"
                test_len = 0
                if test_bytes:
                    ti = self._helpers.analyzeResponse(test_bytes)
                    test_status = str(ti.getStatusCode())
                    test_len = len(test_bytes)
                    to = ti.getBodyOffset()
                    if to < len(test_bytes):
                        test_body = self._helpers.bytesToString(test_bytes[to:])
                similarity, analysis = self._compare_responses(baseline_bytes, baseline_body, test_bytes, test_body)

                has_deny = self._check_deny_keywords(test_body, test_status)
                is_error_json = self._check_error_json(test_body)

                is_vuln = False
                notes = ""
                test_body_len = len(test_body)

                if test_status == "200" and test_body_len > 0 and not has_deny and not is_error_json:
                    if self._is_confident_value_match(self._victim_id, test_body):
                        is_vuln = True
                        notes = "CONFIRMED: Victim data returned!"
                    elif baseline_status == test_status and similarity >= 85:
                        is_vuln = True
                        notes = "HIGH: Similar valid response (Sim=" + str(similarity) + "%) - verify manually"
                    elif baseline_status == test_status and similarity >= 50:
                        notes = "MEDIUM: Partial match (Sim=" + str(similarity) + "%) - verify"
                    else:
                        notes = "LOW: Different response (Sim=" + str(similarity) + "%)"
                elif has_deny:
                    notes = "Blocked: Permission denied detected (Sim=" + str(similarity) + "%)"
                elif is_error_json:
                    notes = "Blocked: Error JSON returned (Sim=" + str(similarity) + "%)"
                elif test_status in ("403", "401"):
                    notes = "Blocked: Auth required (" + test_status + ")"
                elif test_status == "404":
                    notes = "Blocked: Not found (" + test_status + ")"
                elif test_status.startswith("5"):
                    notes = "Error: Server error (" + test_status + ")"
                elif test_status == "200" and test_body_len == 0:
                    notes = "Empty: 200 OK but empty body"
                else:
                    notes = "Other: " + test_status + " (Sim=" + str(similarity) + "%)"
                notes += " | " + analysis

                if self._ai_verify_enabled:
                    ai_verdict = self._ai_verify_result(baseline_body, test_body, baseline_status, test_status, field_name, self._attacker_id, self._victim_id)
                    notes += " | " + ai_verdict

                with self._lock:
                    self._test_count += 1
                    idx = self._test_count
                    if is_vuln:
                        self._vuln_count += 1
                    self._results.append({
                        "idx": idx, "field": field_name, "location": location,
                        "status": test_status, "length": test_len,
                        "similarity": similarity, "vuln": is_vuln, "notes": notes,
                        "original": original_bytes, "modified": modified,
                        "baseline_response": baseline_bytes, "response": test_bytes,
                        "service": service
                    })
                self._log_result(idx, field_name, location, test_status, test_len, similarity, is_vuln, notes)
                self._update_stats_label()
                if is_vuln:
                    vic_pattern = r"(?<![0-9A-Za-z_])" + re.escape(self._victim_id) + r"(?![0-9A-Za-z_])"
                    original_id = self._victim_id if re.search(vic_pattern, original_str) else self._attacker_id
                    swapped_id = self._attacker_id if original_id == self._victim_id else self._victim_id
                    is_html = self._is_html_response(test_bytes)
                    if self._html_skip_issue and is_html:
                        self._callbacks.printOutput("[MANUAL] HTML response detected. Skipping Burp issue registration (toggle is ON).")
                    else:
                        self._register_issue(
                            service,
                            self._helpers.analyzeRequest(self._last_message).getUrl(),
                            field_name, original_id, swapped_id,
                            original_bytes, modified, baseline_bytes, test_bytes, notes
                        )
            except Exception as e:
                self._callbacks.printError("[-] Test error: " + str(e))
        if not tested_any:
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self._panel, "No fields checked!", "Info", JOptionPane.INFORMATION_MESSAGE))

    def _build_modified_request(self, original_str, field_name, location, direction="auto"):
        headers = self._get_headers_from_str(original_str)
        body = self._get_body_from_str(original_str)
        try:
            if location == "URL":
                req_line = headers[0]
                new_req_line = self._smart_replace(req_line, direction)
                if new_req_line is None or new_req_line == req_line:
                    return None
                headers[0] = new_req_line
                return self._build_http_message(headers, body)
            elif location == "Body (Form)":
                new_body = self._smart_replace(body, direction)
                if new_body is None or new_body == body:
                    return None
                return self._build_http_message(headers, new_body)
            elif location == "Body (JSON)":
                jdata = json.loads(body)
                current_val = self._get_json_value(jdata, field_name)
                if current_val is None:
                    return None
                new_val = self._smart_replace(str(current_val), direction)
                if new_val is None or new_val == str(current_val):
                    return None
                self._set_json_value(jdata, field_name, new_val)
                return self._build_http_message(headers, json.dumps(jdata))
            elif location == "Header":
                for i, h in enumerate(headers):
                    if h.startswith(field_name + ":"):
                        new_h = self._smart_replace(h, direction)
                        if new_h is None or new_h == h:
                            return None
                        headers[i] = new_h
                        return self._build_http_message(headers, body)
        except Exception as e:
            self._callbacks.printError("[-] Build error: " + str(e))
        return None

    def _smart_replace(self, text, direction="auto"):
        if direction == "atk_to_vic":
            if self._attacker_id in text:
                return text.replace(self._attacker_id, self._victim_id)
        elif direction == "vic_to_atk":
            if self._victim_id in text:
                return text.replace(self._victim_id, self._attacker_id)
        else:
            if self._victim_id in text:
                return text.replace(self._victim_id, self._attacker_id)
            elif self._attacker_id in text:
                return text.replace(self._attacker_id, self._victim_id)
        return None

    def _build_http_message(self, headers_list, body_str):
        java_headers = ArrayList()
        for h in headers_list:
            java_headers.add(h)
        body_bytes = self._helpers.stringToBytes(body_str)
        for i in range(java_headers.size()):
            h = java_headers.get(i)
            if h.lower().startswith("content-length:"):
                java_headers.set(i, "Content-Length: " + str(len(body_bytes)))
                break
        return self._helpers.buildHttpMessage(java_headers, body_bytes)

    def _get_json_value(self, obj, path):
        parts = path.replace("[", ".").replace("]", "").split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict):
                if part not in current:
                    return None
                current = current[part]
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except:
                    return None
            else:
                return None
        return current

    def _set_json_value(self, obj, path, new_val):
        parts = path.replace("[", ".").replace("]", "").split(".")
        current = obj
        for part in parts[:-1]:
            if isinstance(current, dict):
                current = current[part]
            elif isinstance(current, list):
                current = current[int(part)]
        last = parts[-1]
        if isinstance(current, dict):
            current[last] = new_val
        elif isinstance(current, list):
            current[int(last)] = new_val

    def _compare_responses(self, baseline_bytes, baseline_body, test_bytes, test_body):
        if not baseline_bytes or not test_bytes:
            return 0, "No baseline or test response"
        baseline_info = self._helpers.analyzeResponse(baseline_bytes)
        test_info = self._helpers.analyzeResponse(test_bytes)
        baseline_status = baseline_info.getStatusCode()
        test_status = test_info.getStatusCode()
        baseline_len = len(baseline_bytes)
        test_len = len(test_bytes)
        status_score = 30 if baseline_status == test_status else 0
        if max(baseline_len, test_len) > 0:
            len_score = int((min(baseline_len, test_len) / float(max(baseline_len, test_len))) * 20)
        else:
            len_score = 0
        body_score = self._calc_body_similarity(baseline_body, test_body)
        similarity = status_score + len_score + body_score
        analysis = "Base=" + str(baseline_status) + "|" + str(baseline_len) + " Test=" + str(test_status) + "|" + str(test_len)
        return similarity, analysis

    def _calc_body_similarity(self, s1, s2):
        """
        Similarity of two response bodies, scored 0-50.

        Previously this compared characters index-by-index (ns1[i]==ns2[i]).
        That breaks completely whenever the two bodies differ in length near
        the start - which is exactly what happens during IDOR testing,
        since the swapped id itself is often echoed back in the body and
        attacker/victim ids are rarely the same digit-length (e.g. "7" vs
        "88214"). A single 4-character length difference near the start
        shifts every character after it out of alignment, so two genuinely
        near-identical "same object" responses could score near 0 instead
        of near 50 - directly undermining the HIGH/MEDIUM confidence logic
        built on top of this score.

        difflib.SequenceMatcher finds actual matching blocks regardless of
        their position, so insertions/deletions/length differences no
        longer wreck the score.
        """
        if not s1 and not s2:
            return 50
        if not s1 or not s2:
            return 0
        ns1 = re.sub(r"\s+", " ", s1).strip()
        ns2 = re.sub(r"\s+", " ", s2).strip()
        if not ns1 and not ns2:
            return 50
        # Cap the compared length for performance - large bodies (many KB)
        # made SequenceMatcher noticeably slower under heavy auto-test
        # traffic; a few KB is already enough to tell "same object" from
        # "different object" reliably.
        CAP = 4000
        ratio = difflib.SequenceMatcher(None, ns1[:CAP], ns2[:CAP]).ratio()
        return int(ratio * 50)

    def _log_result(self, idx, field, location, status, length, similarity, is_vuln, notes):
        def run():
            self._res_model.addRow([
                int(idx), field, location, status, int(length),
                int(similarity),
                "YES" if is_vuln else "NO",
                notes
            ])
        SwingUtilities.invokeLater(run)

    def _update_stats_label(self):
        def run():
            if self._vuln_count > 0:
                self._stats.setText(u"\u26A0 Tested: " + str(self._test_count) + " | Vulnerable: " + str(self._vuln_count))
                self._stats.setForeground(Color(180, 0, 0))
            else:
                self._stats.setText("Tested: " + str(self._test_count) + " | Vulnerable: " + str(self._vuln_count))
                self._stats.setForeground(Color(0, 100, 0))
        SwingUtilities.invokeLater(run)

    def _clear_test_cache(self, event):
        self._processed_urls.clear()
        self._callbacks.printOutput("[+] Test deduplication cache cleared. Same requests will be retested.")

    def _clear_results(self, event):
        self._res_model.setRowCount(0)
        with self._lock:
            self._results = []
            self._test_count = 0
            self._vuln_count = 0
        self._update_stats_label()
        self._processed_urls.clear()

    def _view_selected(self, event):
        row = self._res_table.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self._panel, "Select a result row!", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        model_row = self._res_table.convertRowIndexToModel(row)
        if model_row >= len(self._results):
            return
        data = self._results[model_row]

        dialog = JDialog()
        dialog.setTitle("IDOR Test #" + str(data["idx"]) + " - " + data["field"])
        dialog.setSize(1000, 700)

        tabs = JTabbedPane()

        orig = JTextArea(self._helpers.bytesToString(data["original"]))
        orig.setEditable(False)
        orig.setFont(Font("Monospaced", Font.PLAIN, 12))
        tabs.addTab("Original Request", JScrollPane(orig))

        mod = JTextArea(self._helpers.bytesToString(data["modified"]))
        mod.setEditable(False)
        mod.setFont(Font("Monospaced", Font.PLAIN, 12))
        tabs.addTab("Modified Request", JScrollPane(mod))

        base_text = "No baseline"
        if data.get("baseline_response"):
            base_text = self._helpers.bytesToString(data["baseline_response"])
        base = JTextArea(base_text)
        base.setEditable(False)
        base.setFont(Font("Monospaced", Font.PLAIN, 12))
        tabs.addTab("Baseline Response", JScrollPane(base))

        resp_text = "No response"
        if data.get("response"):
            resp_text = self._helpers.bytesToString(data["response"])
        resp = JTextArea(resp_text)
        resp.setEditable(False)
        resp.setFont(Font("Monospaced", Font.PLAIN, 12))
        tabs.addTab("Test Response", JScrollPane(resp))

        summary = JPanel(FlowLayout(FlowLayout.LEFT))
        sim_color = Color(200, 0, 0) if data["similarity"] < 50 else (Color(200, 150, 0) if data["similarity"] < 85 else Color(0, 150, 0))
        sim_label = JLabel("Similarity: " + str(data["similarity"]) + "%")
        sim_label.setFont(Font("Consolas", Font.BOLD, 14))
        sim_label.setForeground(sim_color)
        summary.add(sim_label)
        summary.add(Box.createHorizontalStrut(30))
        summary.add(JLabel("Status: " + data["status"]))
        summary.add(Box.createHorizontalStrut(30))
        summary.add(JLabel("Length: " + str(data["length"])))
        summary.add(Box.createHorizontalStrut(30))
        vuln_label = JLabel("Vulnerable: " + ("YES" if data["vuln"] else "NO"))
        vuln_label.setFont(Font("Consolas", Font.BOLD, 14))
        vuln_label.setForeground(Color(200, 0, 0) if data["vuln"] else Color(0, 100, 0))
        summary.add(vuln_label)

        dialog.add(summary, BorderLayout.NORTH)
        dialog.add(tabs, BorderLayout.CENTER)
        dialog.setVisible(True)

    def _send_repeater(self, event):
        row = self._res_table.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self._panel, "Select a result row!", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        model_row = self._res_table.convertRowIndexToModel(row)
        if model_row >= len(self._results):
            return
        data = self._results[model_row]
        svc = data["service"]
        self._callbacks.sendToRepeater(
            svc.getHost(), svc.getPort(), svc.getProtocol() == "https",
            data["modified"], "IDOR-" + str(data["idx"])
        )
        self._callbacks.printOutput("[+] Sent to Repeater: IDOR-" + str(data["idx"]))

    # ============================================================
    # AI SKILLS SYSTEM - Core Feature
    # ============================================================

    def _open_skill_manager(self, event):
        dialog = JDialog()
        dialog.setTitle("AI Skill Manager")
        dialog.setSize(900, 650)
        panel = JPanel(BorderLayout())

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Define reusable AI test strategies. Enabled skills will auto-execute on 'Run AI Skills'."))
        panel.add(top, BorderLayout.NORTH)

        cols = ["Enabled", "Name", "Description"]
        model = DefaultTableModel(cols, 0)
        table = JTable(model)
        sorter = TableRowSorter(model)
        table.setRowSorter(sorter)

        for skill in self._skills:
            model.addRow([Boolean(skill.get("enabled", False)), skill.get("name", ""), skill.get("description", "")])

        panel.add(JScrollPane(table), BorderLayout.CENTER)

        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))

        def do_add():
            name_field = JTextField(25)
            desc_field = JTextField(40)
            prompt_area = JTextArea(10, 60)
            prompt_area.setLineWrap(True)
            prompt_area.setWrapStyleWord(True)
            prompt_area.setFont(Font("Monospaced", Font.PLAIN, 12))
            prompt_area.setText(
                "You are an expert security tester. Given the HTTP request below, generate a JSON array of tests.\n"
                "Each test object must have: test_name, field, location (URL/Body/Header), original_value, new_value, reason.\n"
                "Only return valid JSON array. No markdown. No explanations."
            )

            inputs = JPanel()
            inputs.setLayout(BoxLayout(inputs, BoxLayout.Y_AXIS))
            inputs.add(JLabel("Skill Name:"))
            inputs.add(name_field)
            inputs.add(JLabel("Description:"))
            inputs.add(desc_field)
            inputs.add(JLabel("AI Prompt (must instruct AI to return JSON array with test_name, field, location, original_value, new_value, reason):"))
            inputs.add(JScrollPane(prompt_area))

            result = JOptionPane.showConfirmDialog(dialog, inputs, "Add New Skill", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
            if result == JOptionPane.OK_OPTION:
                name = name_field.getText().strip()
                desc = desc_field.getText().strip()
                prompt = prompt_area.getText().strip()
                if not name or not prompt:
                    JOptionPane.showMessageDialog(dialog, "Name and Prompt are required!", "Error", JOptionPane.ERROR_MESSAGE)
                    return
                new_skill = {
                    "id": str(uuid.uuid4()),
                    "name": name,
                    "description": desc,
                    "enabled": True,
                    "prompt": prompt
                }
                self._skills.append(new_skill)
                self._save_skills_to_settings()
                model.addRow([Boolean(True), name, desc])
                self._update_pool_label()
                self._callbacks.printOutput("[Skills] Added new skill: " + name)

        def do_edit():
            row = table.getSelectedRow()
            if row < 0:
                JOptionPane.showMessageDialog(dialog, "Select a skill to edit!", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            model_row = table.convertRowIndexToModel(row)
            skill = self._skills[model_row]

            name_field = JTextField(skill.get("name", ""), 25)
            desc_field = JTextField(skill.get("description", ""), 40)
            prompt_area = JTextArea(skill.get("prompt", ""), 10, 60)
            prompt_area.setLineWrap(True)
            prompt_area.setWrapStyleWord(True)
            prompt_area.setFont(Font("Monospaced", Font.PLAIN, 12))

            inputs = JPanel()
            inputs.setLayout(BoxLayout(inputs, BoxLayout.Y_AXIS))
            inputs.add(JLabel("Skill Name:"))
            inputs.add(name_field)
            inputs.add(JLabel("Description:"))
            inputs.add(desc_field)
            inputs.add(JLabel("AI Prompt:"))
            inputs.add(JScrollPane(prompt_area))

            result = JOptionPane.showConfirmDialog(dialog, inputs, "Edit Skill", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
            if result == JOptionPane.OK_OPTION:
                skill["name"] = name_field.getText().strip()
                skill["description"] = desc_field.getText().strip()
                skill["prompt"] = prompt_area.getText().strip()
                self._save_skills_to_settings()
                model.setValueAt(skill["name"], model_row, 1)
                model.setValueAt(skill["description"], model_row, 2)
                self._callbacks.printOutput("[Skills] Edited skill: " + skill["name"])

        def do_delete():
            row = table.getSelectedRow()
            if row < 0:
                JOptionPane.showMessageDialog(dialog, "Select a skill to delete!", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            model_row = table.convertRowIndexToModel(row)
            skill = self._skills[model_row]
            confirm = JOptionPane.showConfirmDialog(dialog, "Delete skill '" + skill.get("name", "") + "'?", "Confirm", JOptionPane.YES_NO_OPTION)
            if confirm == JOptionPane.YES_OPTION:
                del self._skills[model_row]
                model.removeRow(model_row)
                self._save_skills_to_settings()
                self._update_pool_label()
                self._callbacks.printOutput("[Skills] Deleted skill: " + skill.get("name", ""))

        def do_toggle():
            row = table.getSelectedRow()
            if row < 0:
                JOptionPane.showMessageDialog(dialog, "Select a skill to toggle!", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            model_row = table.convertRowIndexToModel(row)
            skill = self._skills[model_row]
            skill["enabled"] = not skill.get("enabled", False)
            model.setValueAt(Boolean(skill["enabled"]), model_row, 0)
            self._save_skills_to_settings()
            self._update_pool_label()
            self._callbacks.printOutput("[Skills] Toggled '" + skill.get("name", "") + "': " + ("ON" if skill["enabled"] else "OFF"))

        def do_view_prompt():
            row = table.getSelectedRow()
            if row < 0:
                JOptionPane.showMessageDialog(dialog, "Select a skill first!", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            model_row = table.convertRowIndexToModel(row)
            skill = self._skills[model_row]
            ta = JTextArea(skill.get("prompt", "No prompt"), 15, 70)
            ta.setEditable(False)
            ta.setFont(Font("Monospaced", Font.PLAIN, 12))
            ta.setLineWrap(True)
            ta.setWrapStyleWord(True)
            JOptionPane.showMessageDialog(dialog, JScrollPane(ta), "Prompt: " + skill.get("name", ""), JOptionPane.INFORMATION_MESSAGE)

        def do_reset_defaults():
            confirm = JOptionPane.showConfirmDialog(dialog, "Reset all skills to defaults? This will delete custom skills.", "Confirm Reset", JOptionPane.YES_NO_OPTION)
            if confirm == JOptionPane.YES_OPTION:
                self._load_default_skills()
                self._save_skills_to_settings()
                model.setRowCount(0)
                for skill in self._skills:
                    model.addRow([Boolean(skill.get("enabled", False)), skill.get("name", ""), skill.get("description", "")])
                self._update_pool_label()
                self._callbacks.printOutput("[Skills] Reset to defaults.")

        btn_add = JButton("Add Skill", actionPerformed=lambda e: do_add())
        btn_edit = JButton("Edit Skill", actionPerformed=lambda e: do_edit())
        btn_delete = JButton("Delete Skill", actionPerformed=lambda e: do_delete())
        btn_toggle = JButton("Toggle Enabled", actionPerformed=lambda e: do_toggle())
        btn_view = JButton("View Prompt", actionPerformed=lambda e: do_view_prompt())
        btn_reset = JButton("Reset Defaults", actionPerformed=lambda e: do_reset_defaults())

        btn_panel.add(btn_add)
        btn_panel.add(btn_edit)
        btn_panel.add(btn_delete)
        btn_panel.add(btn_toggle)
        btn_panel.add(btn_view)
        btn_panel.add(btn_reset)

        panel.add(btn_panel, BorderLayout.SOUTH)
        dialog.add(panel)
        dialog.setVisible(True)

    def _run_skills_on_loaded(self, event):
        if not self._last_message:
            JOptionPane.showMessageDialog(self._panel, "Load a request first!", "Error", JOptionPane.WARNING_MESSAGE)
            return
        if not self._ai_enabled:
            JOptionPane.showMessageDialog(self._panel, "Turn AI Extract ON first!", "Error", JOptionPane.WARNING_MESSAGE)
            return
        active_skills = [s for s in self._skills if s.get("enabled", False)]
        if not active_skills:
            JOptionPane.showMessageDialog(self._panel, "No skills are enabled! Open Skill Manager and enable at least one.", "No Skills", JOptionPane.WARNING_MESSAGE)
            return
        req_str = self._helpers.bytesToString(self._last_message.getRequest())
        self._callbacks.printOutput("[Skills] Running " + str(len(active_skills)) + " active skill(s) on loaded request...")
        t = threading.Thread(target=self._run_ai_skills_thread, args=(req_str, self._last_message))
        t.setDaemon(True)
        t.start()

    def _run_ai_skills_thread(self, req_str, messageInfo):
        try:
            api_key = self._ai_key_field.getText()
            if not api_key or not api_key.strip():
                self._callbacks.printOutput("[-] Skills: No API key available")
                return
            api_key = api_key.strip()

            service = messageInfo.getHttpService()
            original_bytes = messageInfo.getRequest()
            original_str = req_str

            # Get baseline first
            self._callbacks.printOutput("[Skills] Getting baseline response...")
            baseline_resp = self._callbacks.makeHttpRequest(service, original_bytes)
            baseline_bytes = baseline_resp.getResponse() if baseline_resp else None
            baseline_body = ""
            baseline_status = "Err"
            if baseline_bytes:
                bi = self._helpers.analyzeResponse(baseline_bytes)
                baseline_status = str(bi.getStatusCode())
                bo = bi.getBodyOffset()
                if bo < len(baseline_bytes):
                    baseline_body = self._helpers.bytesToString(baseline_bytes[bo:])

            headers = self._get_headers_from_str(req_str)
            body = self._get_body_from_str(req_str)
            url_line = headers[0] if headers else ""

            active_skills = [s for s in self._skills if s.get("enabled", False)]
            total_tests = 0

            for skill in active_skills:
                skill_name = skill.get("name", "Unnamed")
                self._callbacks.printOutput("[Skills] Executing skill: " + skill_name)

                prompt = skill.get("prompt", "")
                full_prompt = (
                    prompt + "\n\n"
                    "HTTP REQUEST TO ANALYZE:\n"
                    "URL: " + url_line[:500] + "\n"
                    "BODY: " + body[:3000] + "\n"
                    "HEADERS (excluding cookies):\n"
                )
                # Add non-cookie headers
                for h in headers[1:]:
                    if not h.lower().startswith("cookie:") and not h.lower().startswith("authorization:"):
                        full_prompt += h + "\n"

                payload = {
                    "model": self._ai_model,
                    "messages": [{"role": "user", "content": full_prompt}],
                    "temperature": 0.2,
                    "max_tokens": 4000
                }

                try:
                    data = self._make_ai_request(payload, api_key, timeout=30)
                    content = None
                    if "choices" in data and len(data["choices"]) > 0:
                        choice = data["choices"][0]
                        if "message" in choice and "content" in choice["message"]:
                            content = choice["message"]["content"]
                    if not content:
                        self._callbacks.printOutput("[-] Skills: " + skill_name + " returned empty response")
                        continue

                    self._callbacks.printOutput("[Skills] " + skill_name + " raw response length: " + str(len(content)))
                    result = self._parse_ai_json(content)
                    if result is None or not isinstance(result, list):
                        self._callbacks.printOutput("[-] Skills: " + skill_name + " response not parseable as JSON array")
                        continue

                    self._callbacks.printOutput("[Skills] " + skill_name + " generated " + str(len(result)) + " test(s)")

                    for test_item in result:
                        if not isinstance(test_item, dict):
                            continue
                        try:
                            test_name = str(test_item.get("test_name", "unnamed"))
                            field = str(test_item.get("field", ""))
                            location = str(test_item.get("location", "Body")).lower()
                            orig_val = str(test_item.get("original_value", ""))
                            new_val = str(test_item.get("new_value", ""))
                            reason = str(test_item.get("reason", ""))

                            if not field or not new_val:
                                continue

                            total_tests += 1
                            self._execute_skill_test(
                                service, original_bytes, original_str, baseline_bytes, baseline_body, baseline_status,
                                skill_name, test_name, field, location, orig_val, new_val, reason
                            )
                        except Exception as test_e:
                            self._callbacks.printError("[-] Skills test error: " + str(test_e))

                except Exception as skill_e:
                    self._callbacks.printError("[-] Skills execution error for " + skill_name + ": " + str(skill_e))

            self._callbacks.printOutput("[Skills] All skills complete. Total AI-generated tests executed: " + str(total_tests))
        except Exception as e:
            self._callbacks.printError("[-] Skills thread error: " + str(e))

    def _execute_skill_test(self, service, original_bytes, original_str, baseline_bytes, baseline_body, baseline_status,
                            skill_name, test_name, field, location, orig_val, new_val, reason):
        try:
            modified_bytes = self._apply_skill_modification(original_str, field, location, orig_val, new_val)
            if modified_bytes is None:
                self._callbacks.printOutput("[Skills] Could not apply modification for: " + test_name)
                return

            mod_str = self._helpers.bytesToString(modified_bytes)
            if mod_str == original_str:
                self._callbacks.printOutput("[Skills] No change for: " + test_name)
                return

            self._callbacks.printOutput("[Skills] Testing: " + test_name + " (" + field + " -> " + new_val[:30] + ")")
            test_resp = self._callbacks.makeHttpRequest(service, modified_bytes)
            test_bytes = test_resp.getResponse() if test_resp else None
            test_body = ""
            test_status = "Err"
            test_len = 0
            if test_bytes:
                ti = self._helpers.analyzeResponse(test_bytes)
                test_status = str(ti.getStatusCode())
                test_len = len(test_bytes)
                to = ti.getBodyOffset()
                if to < len(test_bytes):
                    test_body = self._helpers.bytesToString(test_bytes[to:])

            similarity, analysis = self._compare_responses(baseline_bytes, baseline_body, test_bytes, test_body)
            has_deny = self._check_deny_keywords(test_body, test_status)
            is_error_json = self._check_error_json(test_body)

            is_vuln = False
            notes = "[Skill: " + skill_name + "] " + reason + " | "
            test_body_len = len(test_body)

            if test_status == "200" and test_body_len > 0 and not has_deny and not is_error_json:
                if self._is_confident_value_match(new_val, test_body):
                    is_vuln = True
                    notes += "CONFIRMED: Injected value found in response!"
                elif baseline_status == test_status and similarity >= 85:
                    is_vuln = True
                    notes += "HIGH: Similar valid response (Sim=" + str(similarity) + "%) - verify manually"
                elif baseline_status == test_status and similarity >= 50:
                    notes += "MEDIUM: Partial match (Sim=" + str(similarity) + "%) - verify"
                else:
                    notes += "LOW: Different response (Sim=" + str(similarity) + "%)"
            elif has_deny:
                notes += "Blocked: Permission denied (Sim=" + str(similarity) + "%)"
            elif is_error_json:
                notes += "Blocked: Error JSON (Sim=" + str(similarity) + "%)"
            elif test_status in ("403", "401"):
                notes += "Blocked: Auth required (" + test_status + ")"
            elif test_status == "404":
                notes += "Blocked: Not found (" + test_status + ")"
            elif test_status.startswith("5"):
                notes += "Error: Server error (" + test_status + ")"
            elif test_status == "200" and test_body_len == 0:
                notes += "Empty: 200 OK but empty body"
            else:
                notes += "Other: " + test_status + " (Sim=" + str(similarity) + "%)"
            notes += " | " + analysis

            if self._ai_verify_enabled:
                ai_verdict = self._ai_verify_result(baseline_body, test_body, baseline_status, test_status, field, orig_val, new_val)
                notes += " | " + ai_verdict

            with self._lock:
                self._test_count += 1
                idx = self._test_count
                if is_vuln:
                    self._vuln_count += 1
                self._results.append({
                    "idx": idx, "field": field + " [" + test_name + "]", "location": "AI-Skill",
                    "status": test_status, "length": test_len,
                    "similarity": similarity, "vuln": is_vuln, "notes": notes,
                    "original": original_bytes, "modified": modified_bytes,
                    "baseline_response": baseline_bytes, "response": test_bytes,
                    "service": service
                })
            self._log_result(idx, field + " [" + test_name + "]", "AI-Skill", test_status, test_len, similarity, is_vuln, notes)
            self._update_stats_label()

            if is_vuln:
                # Get the URL from the original request
                req_info = self._helpers.analyzeRequest(original_bytes)
                url = req_info.getUrl()
                is_html = self._is_html_response(test_bytes)
                if self._html_skip_issue and is_html:
                    self._callbacks.printOutput("[Skills] HTML response. Skipping issue registration.")
                else:
                    self._register_issue(
                        service, url, field + " [" + skill_name + "]", orig_val, new_val,
                        original_bytes, modified_bytes, baseline_bytes, test_bytes, notes
                    )
                self._callbacks.printOutput("[Skills] *** VULNERABLE: " + str(url) + " [" + test_name + "] ***")

        except Exception as e:
            self._callbacks.printError("[-] Skill test execution error: " + str(e))

    def _apply_skill_modification(self, original_str, field, location, orig_val, new_val):
        headers = self._get_headers_from_str(original_str)
        body = self._get_body_from_str(original_str)
        try:
            if location in ("url", "query", "path", "url-path"):
                req_line = headers[0]
                # Prefer the precise "field=value" pattern first. A raw
                # substring replace of orig_val alone is risky when orig_val
                # is short/generic (e.g. "1") since it can match an unrelated
                # part of the URL (another param, a path segment, etc.).
                new_req_line = req_line.replace(field + "=" + orig_val, field + "=" + new_val)
                if new_req_line == req_line and orig_val and orig_val in req_line:
                    new_req_line = req_line.replace(orig_val, new_val)
                if new_req_line == req_line:
                    new_req_line = req_line.replace(field + "=", field + "=" + new_val)
                if new_req_line == req_line:
                    return None
                headers[0] = new_req_line
                return self._build_http_message(headers, body)
            elif location in ("body", "form", "post"):
                new_body = body.replace(field + "=" + orig_val, field + "=" + new_val)
                if new_body == body and orig_val and orig_val in body:
                    new_body = body.replace(orig_val, new_val)
                if new_body == body:
                    new_body = body.replace(field + "=", field + "=" + new_val)
                if new_body == body:
                    return None
                return self._build_http_message(headers, new_body)
            elif location in ("json", "body-json"):
                if not body.strip().startswith("{"):
                    return None
                jdata = json.loads(body)
                current_val = self._get_json_value(jdata, field)
                if current_val is None:
                    # Try adding the field if it doesn't exist (mass assignment style)
                    parts = field.replace("[", ".").replace("]", "").split(".")
                    current = jdata
                    for part in parts[:-1]:
                        if isinstance(current, dict):
                            if part not in current:
                                current[part] = {}
                            current = current[part]
                        else:
                            return None
                    last = parts[-1]
                    if isinstance(current, dict):
                        current[last] = new_val
                        return self._build_http_message(headers, json.dumps(jdata))
                    return None
                new_val_applied = str(current_val).replace(str(orig_val), str(new_val)) if orig_val else new_val
                if str(current_val) == new_val_applied:
                    return None
                self._set_json_value(jdata, field, new_val_applied)
                return self._build_http_message(headers, json.dumps(jdata))
            elif location in ("header", "headers"):
                for i, h in enumerate(headers):
                    if h.lower().startswith(field.lower() + ":"):
                        if orig_val and orig_val in h:
                            new_h = h.replace(orig_val, new_val)
                        else:
                            new_h = field + ": " + new_val
                        if new_h == h:
                            return None
                        headers[i] = new_h
                        return self._build_http_message(headers, body)
                # If header not found, add it
                headers.append(field + ": " + new_val)
                return self._build_http_message(headers, body)
            else:
                # Fallback: try body then URL
                if orig_val and orig_val in body:
                    new_body = body.replace(orig_val, new_val)
                    return self._build_http_message(headers, new_body)
                elif orig_val and orig_val in headers[0]:
                    new_req_line = headers[0].replace(orig_val, new_val)
                    headers[0] = new_req_line
                    return self._build_http_message(headers, body)
        except Exception as e:
            self._callbacks.printError("[-] Skill modification error: " + str(e))
        return None
