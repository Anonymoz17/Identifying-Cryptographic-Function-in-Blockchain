"""Static Analysis tab for Results Page.

Shows detailed static analysis findings with:
- Filterable findings table
- Confidence slider filtering
- Finding type checkboxes
- Detailed finding view on selection
- Copy-to-clipboard functionality
- Sortable table columns
- Pagination for large datasets
"""

from typing import TYPE_CHECKING, Optional, List
import customtkinter as ctk
from ui.results_components import (
    FilterPanel, SectionHeader, FindingsTable, CopyButton, COLORS
)

if TYPE_CHECKING:
    from pages.results_model import ResultsDataModel, Finding


class StaticTab(ctk.CTkFrame):
    """Tab showing static analysis findings with filtering, sorting, and pagination."""

    # Pagination settings
    FINDINGS_PER_PAGE = 50

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLORS['bg'], **kwargs)
        self.data_model: 'ResultsDataModel' = None
        self.current_filters = {}
        self.selected_finding = None

        # Pagination state
        self.current_page = 1
        self.total_pages = 1
        self.all_findings = []  # Cache all filtered findings

        # Sorting state
        self.sort_column = None  # 'confidence', 'name', etc.
        self.sort_ascending = True

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Filter panel
        self.filter_panel = FilterPanel(
            self,
            on_change=self._on_filter_changed,
            finding_types=['constant_table', 'signature_pattern', 'instruction_pattern']
        )
        self.filter_panel.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))

        # Content area
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        content.grid_rowconfigure(1, weight=1)
        content.grid_columnconfigure((0, 1), weight=1)

        # Left side - Findings table
        left_section = ctk.CTkFrame(content, fg_color="transparent")
        left_section.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 8))
        left_section.grid_rowconfigure(1, weight=1)
        left_section.grid_columnconfigure(0, weight=1)

        header = SectionHeader(
            left_section,
            title="Findings"
        )
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 8))

        # Findings table with sort callback
        self.findings_table = FindingsTable(
            left_section,
            on_sort_column=self._sort_findings  # Pass sort callback
        )
        self.findings_table.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)

        # Right side - Details panel
        details_frame = ctk.CTkFrame(content, fg_color=COLORS['card_bg'], corner_radius=8)
        details_frame.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(8, 0))
        details_frame.grid_rowconfigure(1, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)

        detail_header = ctk.CTkLabel(
            details_frame,
            text="Finding Details",
            font=("Roboto", 12, "bold"),
            text_color=COLORS['text']
        )
        detail_header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))

        # Details scroll area
        self.details_scroll = ctk.CTkScrollableFrame(
            details_frame,
            fg_color="transparent"
        )
        self.details_scroll.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.details_scroll.grid_columnconfigure(0, weight=1)

        # No selection message
        self.no_selection_label = ctk.CTkLabel(
            self.details_scroll,
            text="Select a finding to view details",
            font=("Roboto", 11),
            text_color=COLORS['text_secondary']
        )
        self.no_selection_label.pack(pady=20)

    def load_data(self, data_model: 'ResultsDataModel'):
        """Load data into the tab."""
        self.data_model = data_model
        self._refresh_findings()

    def _on_filter_changed(self, filters: dict):
        """Handle filter change."""
        self.current_filters = filters
        self.current_page = 1  # Reset to first page on filter change
        self._refresh_findings()

    def _refresh_findings(self):
        """Refresh the findings table with current filters (paginated)."""
        if not self.data_model:
            return

        # Get all findings, then filter by MAX confidence (shows findings with confidence <= threshold)
        # When slider is at 5%, shows findings with confidence 0-5% (low confidence)
        max_conf = self.current_filters.get('min_confidence', 1.0)
        all_findings = self.data_model.get_static_findings(min_confidence=0.0)
        self.all_findings = [f for f in all_findings if f.confidence <= max_conf]

        # Calculate total pages
        if self.all_findings:
            self.total_pages = (len(self.all_findings) + self.FINDINGS_PER_PAGE - 1) // self.FINDINGS_PER_PAGE
        else:
            self.total_pages = 1

        # Clamp current page
        if self.current_page > self.total_pages:
            self.current_page = self.total_pages

        # Display current page
        self._display_current_page()
        self._update_pagination_controls()

    def _sort_findings(self, column: str):
        """Sort findings by a column. Clicking same column toggles ascending/descending."""
        # Toggle sort direction if clicking the same column
        if self.sort_column == column:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = column
            self.sort_ascending = False  # Default to descending for confidence (shows high first)
            if column in ['name', 'type']:
                self.sort_ascending = True  # Alphabetical ascending

        # Sort the findings list
        if column == 'confidence':
            self.all_findings.sort(
                key=lambda f: f.confidence,
                reverse=not self.sort_ascending
            )
        elif column == 'name':
            self.all_findings.sort(
                key=lambda f: (f.name or f.type).lower(),
                reverse=not self.sort_ascending
            )
        elif column == 'type':
            self.all_findings.sort(
                key=lambda f: f.type.lower(),
                reverse=not self.sort_ascending
            )

        # Reset to page 1 and redisplay
        self.current_page = 1
        self._display_current_page()
        self._update_pagination_controls()

    def _display_current_page(self):
        """Display findings for the current page (efficiently creates only visible rows)."""
        # Clear table
        self.findings_table.clear_table()

        if not self.all_findings:
            no_results = ctk.CTkLabel(
                self.findings_table.scroll_frame,
                text="No findings match the current filters",
                font=("Roboto", 11),
                text_color=COLORS['text_secondary']
            )
            no_results.pack(pady=20)
            return

        # Calculate page boundaries
        start_idx = (self.current_page - 1) * self.FINDINGS_PER_PAGE
        end_idx = min(start_idx + self.FINDINGS_PER_PAGE, len(self.all_findings))

        # Display findings for current page (only 50 widgets created at a time)
        for finding in self.all_findings[start_idx:end_idx]:
            self.findings_table.add_finding(
                finding_id=finding.id,
                name=finding.name or finding.type,
                confidence=finding.confidence,
                finding_type=finding.type,
                address=finding.address,  # Pass address for location info
                on_click=lambda f=finding: self._show_finding_details(f)
            )

    def _update_pagination_controls(self):
        """Update pagination buttons and info."""
        # Create pagination frame if it doesn't exist
        if not hasattr(self, 'pagination_frame'):
            pagination_frame = ctk.CTkFrame(self, fg_color="transparent")
            pagination_frame.grid(row=2, column=0, sticky="ew", padx=16, pady=(12, 0))
            pagination_frame.grid_columnconfigure(1, weight=1)
            self.pagination_frame = pagination_frame

            # Previous button
            self.prev_btn = ctk.CTkButton(
                pagination_frame,
                text="← Previous",
                width=100,
                height=32,
                command=self._previous_page
            )
            self.prev_btn.grid(row=0, column=0, sticky="w", padx=(0, 8))

            # Page info label
            self.page_info_label = ctk.CTkLabel(
                pagination_frame,
                text="",
                font=("Roboto", 11),
                text_color=COLORS['text_secondary']
            )
            self.page_info_label.grid(row=0, column=1, sticky="ew", padx=8)

            # Next button
            self.next_btn = ctk.CTkButton(
                pagination_frame,
                text="Next →",
                width=100,
                height=32,
                command=self._next_page
            )
            self.next_btn.grid(row=0, column=2, sticky="e", padx=(8, 0))

        # Update button states and labels
        total_results = len(self.all_findings)
        page_text = f"Page {self.current_page} of {self.total_pages} ({total_results} total findings)"
        self.page_info_label.configure(text=page_text)

        # Enable/disable navigation buttons
        self.prev_btn.configure(state="normal" if self.current_page > 1 else "disabled")
        self.next_btn.configure(state="normal" if self.current_page < self.total_pages else "disabled")

    def _previous_page(self):
        """Go to previous page."""
        if self.current_page > 1:
            self.current_page -= 1
            self._display_current_page()
            self._update_pagination_controls()

    def _next_page(self):
        """Go to next page."""
        if self.current_page < self.total_pages:
            self.current_page += 1
            self._display_current_page()
            self._update_pagination_controls()

    def _show_finding_details(self, finding: 'Finding'):
        """Show detailed information for a selected finding."""
        self.selected_finding = finding

        # Clear previous details
        for widget in self.details_scroll.winfo_children():
            widget.destroy()

        # Build details view
        details_content = ctk.CTkFrame(self.details_scroll, fg_color="transparent")
        details_content.pack(fill="x", padx=0, pady=0)
        details_content.grid_columnconfigure(0, weight=1)

        # ====== HEADER SECTION ======
        # Finding ID
        id_frame = ctk.CTkFrame(details_content, fg_color="transparent")
        id_frame.pack(fill="x", padx=0, pady=4)
        id_frame.grid_columnconfigure(1, weight=1)

        id_label = ctk.CTkLabel(
            id_frame,
            text="ID:",
            font=("Roboto", 10, "bold"),
            text_color=COLORS['text_secondary']
        )
        id_label.grid(row=0, column=0, sticky="w")

        id_value = ctk.CTkLabel(
            id_frame,
            text=finding.id,
            font=("Roboto", 10),
            text_color=COLORS['primary']
        )
        id_value.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        # Type
        type_label = ctk.CTkLabel(
            details_content,
            text=f"Type: {finding.type}",
            font=("Roboto", 10),
            text_color=COLORS['text']
        )
        type_label.pack(anchor="w", padx=0, pady=4)

        # Confidence
        conf_color = self._get_confidence_color(finding.confidence)
        conf_label = ctk.CTkLabel(
            details_content,
            text=f"Confidence: {finding.confidence:.0%}",
            font=("Roboto", 10),
            text_color=conf_color
        )
        conf_label.pack(anchor="w", padx=0, pady=4)

        # ====== LOCATION SECTION ======
        location_data = finding.additional_data.get('address_or_range') if finding.additional_data else None
        section_name = finding.additional_data.get('section') if finding.additional_data else None
        function_name = finding.additional_data.get('function_name') if finding.additional_data else None

        # Show location header if we have any location data
        if finding.address or location_data or section_name or function_name:
            location_header = ctk.CTkLabel(
                details_content,
                text="Location:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            location_header.pack(anchor="w", padx=0, pady=(8, 4))

        # Address (prefer finding.address, fallback to location_data)
        display_address = finding.address
        if not display_address and location_data:
            if isinstance(location_data, dict):
                display_address = location_data.get('start')

        if display_address:
            addr_frame = ctk.CTkFrame(details_content, fg_color="transparent")
            addr_frame.pack(fill="x", padx=0, pady=4)
            addr_frame.grid_columnconfigure(1, weight=1)

            addr_label = ctk.CTkLabel(
                addr_frame,
                text="Address:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            addr_label.grid(row=0, column=0, sticky="w")

            addr_value = ctk.CTkLabel(
                addr_frame,
                text=display_address,
                font=("Roboto", 10),
                text_color=COLORS['primary'],
                wraplength=180
            )
            addr_value.grid(row=0, column=1, sticky="ew", padx=(4, 0))

            # Copy button
            copy_btn = CopyButton(
                addr_frame,
                text="Copy",
                copy_text=display_address,
                width=50,
                height=24
            )
            copy_btn.grid(row=0, column=2, sticky="e", padx=(4, 0))

        # Address range (end address) if available
        if location_data and isinstance(location_data, dict):
            end_addr = location_data.get('end')
            if end_addr and end_addr != display_address:
                range_frame = ctk.CTkFrame(details_content, fg_color="transparent")
                range_frame.pack(fill="x", padx=0, pady=4)

                range_label = ctk.CTkLabel(
                    range_frame,
                    text=f"Range: {display_address} → {end_addr}",
                    font=("Roboto", 9),
                    text_color=COLORS['text'],
                    wraplength=250
                )
                range_label.pack(anchor="w", padx=0, pady=2)

            # Size if available
            size = location_data.get('size')
            if size:
                size_frame = ctk.CTkFrame(details_content, fg_color="transparent")
                size_frame.pack(fill="x", padx=0, pady=4)

                size_label = ctk.CTkLabel(
                    size_frame,
                    text=f"Size: {size} bytes",
                    font=("Roboto", 9),
                    text_color=COLORS['text'],
                )
                size_label.pack(anchor="w", padx=0, pady=2)

        # Section name
        if section_name:
            section_frame = ctk.CTkFrame(details_content, fg_color="transparent")
            section_frame.pack(fill="x", padx=0, pady=4)

            section_label = ctk.CTkLabel(
                section_frame,
                text="Section:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            section_label.pack(side="left")

            section_value = ctk.CTkLabel(
                section_frame,
                text=section_name,
                font=("Roboto", 10),
                text_color=COLORS['primary'],
            )
            section_value.pack(side="left", padx=(4, 0))

        # Function name
        if function_name:
            fn_frame = ctk.CTkFrame(details_content, fg_color="transparent")
            fn_frame.pack(fill="x", padx=0, pady=4)

            fn_label = ctk.CTkLabel(
                fn_frame,
                text="Function:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            fn_label.pack(side="left")

            fn_value = ctk.CTkLabel(
                fn_frame,
                text=function_name,
                font=("Roboto", 10),
                text_color=COLORS['primary'],
                wraplength=180
            )
            fn_value.pack(side="left", padx=(4, 0), fill="x", expand=True)

        # Detection metadata section
        # Show reason tags and evidence tags if available
        reason_tags = finding.additional_data.get('reason_tags', []) if finding.additional_data else []
        evidence_tags = finding.additional_data.get('evidence_tags', []) if finding.additional_data else []

        if reason_tags or evidence_tags:
            metadata_header = ctk.CTkLabel(
                details_content,
                text="Detection Metadata:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            metadata_header.pack(anchor="w", padx=0, pady=(8, 4))

            # Show reason tags
            if reason_tags:
                tags_str = ", ".join(reason_tags)
                tags_label = ctk.CTkLabel(
                    details_content,
                    text=f"Detection Tags: {tags_str}",
                    font=("Roboto", 9),
                    text_color=COLORS['text'],
                    wraplength=250,
                    justify="left"
                )
                tags_label.pack(anchor="w", padx=0, pady=2)

            # Show evidence tags if different from reason tags
            if evidence_tags and evidence_tags != reason_tags:
                ev_tags_str = ", ".join(evidence_tags)
                ev_label = ctk.CTkLabel(
                    details_content,
                    text=f"Evidence: {ev_tags_str}",
                    font=("Roboto", 9),
                    text_color=COLORS['text'],
                    wraplength=250,
                    justify="left"
                )
                ev_label.pack(anchor="w", padx=0, pady=2)

        # ====== PHASE 2: CONTEXT ENRICHMENT SECTION ======
        # Display callers, callees, and call chain if available (Phase 2)
        callers = finding.additional_data.get('callers', []) if finding.additional_data else []
        callees = finding.additional_data.get('callees', []) if finding.additional_data else []
        call_chain = finding.additional_data.get('call_chain', []) if finding.additional_data else []

        if callers or callees or call_chain:
            context_header = ctk.CTkLabel(
                details_content,
                text="Context (Phase 2):",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['primary']
            )
            context_header.pack(anchor="w", padx=0, pady=(8, 4))

            # Show callers (who calls this function)
            if callers:
                callers_str = ", ".join(callers) if isinstance(callers, list) else str(callers)
                callers_label = ctk.CTkLabel(
                    details_content,
                    text=f"Called By: {callers_str}",
                    font=("Roboto", 9),
                    text_color=COLORS['text'],
                    wraplength=250,
                    justify="left"
                )
                callers_label.pack(anchor="w", padx=0, pady=2)

            # Show callees (what this function calls)
            if callees:
                callees_str = ", ".join(callees) if isinstance(callees, list) else str(callees)
                callees_label = ctk.CTkLabel(
                    details_content,
                    text=f"Calls: {callees_str}",
                    font=("Roboto", 9),
                    text_color=COLORS['text'],
                    wraplength=250,
                    justify="left"
                )
                callees_label.pack(anchor="w", padx=0, pady=2)

            # Show call chain (path from main to this function)
            if call_chain:
                chain_str = " → ".join(call_chain) if isinstance(call_chain, list) else str(call_chain)
                chain_label = ctk.CTkLabel(
                    details_content,
                    text=f"Call Chain: {chain_str}",
                    font=("Roboto", 9),
                    text_color=COLORS['text'],
                    wraplength=250,
                    justify="left"
                )
                chain_label.pack(anchor="w", padx=0, pady=2)

        # Separator
        sep = ctk.CTkFrame(details_content, height=1, fg_color=COLORS['border'])
        sep.pack(fill="x", padx=0, pady=8)

        # ====== EVIDENCE SECTION ======
        if finding.evidence:
            evidence_label = ctk.CTkLabel(
                details_content,
                text="Why Flagged (Evidence):",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            evidence_label.pack(anchor="w", padx=0, pady=(8, 4))

            evidence_text = ctk.CTkLabel(
                details_content,
                text=finding.evidence,
                font=("Roboto", 9),
                text_color=COLORS['text'],
                justify="left",
                wraplength=250
            )
            evidence_text.pack(anchor="w", padx=0, pady=(0, 8))

        # ====== ACTION SECTION ======
        # Show how to fix based on type
        fix_info = self._get_fix_suggestion(finding)
        if fix_info:
            fix_label = ctk.CTkLabel(
                details_content,
                text="How to Fix:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['success']
            )
            fix_label.pack(anchor="w", padx=0, pady=(8, 4))

            fix_text = ctk.CTkLabel(
                details_content,
                text=fix_info,
                font=("Roboto", 9),
                text_color=COLORS['text'],
                justify="left",
                wraplength=250
            )
            fix_text.pack(anchor="w", padx=0, pady=(0, 8))

        # Additional data (if any remaining - exclude location/metadata fields already shown)
        fields_to_exclude = [
            'reason_tags', 'evidence_tags', 'evidence_snippet', 'evidence', 'offset', 'function',
            'section', 'file_offset', 'virtual_address', 'module', 'address', 'address_or_range',
            'function_name', 'callers', 'callees', 'call_chain', 'source', 'match_location'
        ]
        other_data = {k: v for k, v in (finding.additional_data or {}).items()
                      if k not in fields_to_exclude}

        if other_data:
            additional_label = ctk.CTkLabel(
                details_content,
                text="Additional Metadata:",
                font=("Roboto", 10, "bold"),
                text_color=COLORS['text_secondary']
            )
            additional_label.pack(anchor="w", padx=0, pady=(8, 4))

            # Show all remaining data (both expected and unexpected fields help with debugging)
            for key, value in other_data.items():
                # Format value nicely
                value_str = str(value)
                if len(value_str) > 80:
                    value_str = value_str[:77] + "..."
                field_label = key.replace('_', ' ').title()
                info_text = ctk.CTkLabel(
                    details_content,
                    text=f"{field_label}: {value_str}",
                    font=("Roboto", 9),
                    text_color=COLORS['text'],
                    wraplength=250,
                    justify="left"
                )
                info_text.pack(anchor="w", padx=0, pady=2)

    def _get_fix_suggestion(self, finding: 'Finding') -> Optional[str]:
        """Get actionable fix suggestion based on finding type and data."""
        # Extract contextual info for smarter suggestions
        name = finding.name or ""
        confidence = finding.confidence
        additional_data = finding.additional_data or {}
        function_name = additional_data.get('function_name', '')
        callers = additional_data.get('callers', [])

        # Build data-driven suggestions
        suggestions = {
            'constant_table': self._suggest_for_constant_table(name, confidence, additional_data),
            'sbox_table': self._suggest_for_sbox(name, confidence),
            'known_crypto_constant': self._suggest_for_known_constant(name, confidence),
            'signature': self._suggest_for_signature(name, function_name, confidence),
            'signature_pattern': self._suggest_for_signature(name, function_name, confidence),
            'instruction_pattern': self._suggest_for_instruction_pattern(confidence, additional_data),
            'high_entropy_region': self._suggest_for_entropy(confidence, additional_data),
        }

        default_suggestion = f"Review this {finding.type} finding and verify it aligns with your cryptographic implementation requirements."
        return suggestions.get(finding.type, default_suggestion)

    def _suggest_for_constant_table(self, name: str, confidence: float, data: dict) -> str:
        """Suggestion for constant table findings."""
        if confidence >= 0.9:
            return f"High-confidence constant table detected ({name}). Replace with standard library implementations of {name.split('_')[0]} if possible."
        elif confidence >= 0.7:
            return f"Likely {name} constant table. Verify by cross-referencing against known {name.split('_')[0]} values and consider using established crypto libraries."
        else:
            return f"Potential {name} constant detected. Analyze pattern context and review against known algorithm specifications."

    def _suggest_for_sbox(self, name: str, confidence: float) -> str:
        """Suggestion for S-box table findings."""
        if confidence >= 0.85:
            return "S-box table detected with high confidence. Verify algorithm family and consider using vetted cryptographic library implementations."
        else:
            return "Potential S-box or lookup table detected. Cross-reference bytes against known substitution patterns and algorithm specifications."

    def _suggest_for_known_constant(self, name: str, confidence: float) -> str:
        """Suggestion for known crypto constant findings."""
        algo = name.split('_')[0] if '_' in name else name
        return f"Known {algo} constant detected ({name}). Part of algorithm initialization. Review usage context to ensure correct implementation."

    def _suggest_for_signature(self, name: str, function_name: str, confidence: float) -> str:
        """Suggestion for signature findings."""
        if confidence >= 0.85:
            if function_name and function_name not in ["Unknown", ""]:
                return f"Function '{function_name}' matches {name} signature with high confidence. Consider replacing with standard {name} implementation from OpenSSL, libsodium, or similar."
            else:
                return f"High-confidence {name} function signature detected. Replace with vetted cryptographic library implementation if possible."
        else:
            return f"Potential {name} function detected. Verify implementation and consider using established cryptographic libraries."

    def _suggest_for_instruction_pattern(self, confidence: float, data: dict) -> str:
        """Suggestion for instruction pattern findings."""
        function_name = data.get('function_name', '')
        if confidence >= 0.8:
            msg = "Strong cryptographic instruction pattern detected (XOR, shifts, rotations)."
            if function_name:
                msg += f" The function '{function_name}' likely implements crypto operations."
            msg += " Ensure proper key management and consider using established libraries for better security."
            return msg
        elif confidence >= 0.5:
            return "Cryptographic instruction patterns detected. Verify context and ensure secure key handling practices are followed."
        else:
            return "Potential cryptographic instructions detected. Review function context to determine actual crypto usage and security implications."

    def _suggest_for_entropy(self, confidence: float, data: dict) -> str:
        """Suggestion for entropy findings."""
        size = data.get('size', 'unknown')
        if confidence >= 0.75:
            return f"High entropy region detected (likely crypto key or ciphertext). Size: {size}. Ensure proper handling of sensitive cryptographic material."
        elif confidence >= 0.5:
            return f"Moderate entropy region detected. Could be compressed data, encrypted data, or random material. Size: {size}. Investigate context."
        else:
            return f"Low-confidence entropy anomaly. Size: {size}. Verify it's not a false positive from compressed or obfuscated code."

    @staticmethod
    def _get_confidence_color(confidence: float) -> str:
        """Get color based on confidence level."""
        if confidence >= 0.8:
            return COLORS['success']  # green
        elif confidence >= 0.5:
            return COLORS['warning']  # yellow
        else:
            return COLORS['danger']  # red
