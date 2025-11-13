"""Export engine for Results Page.

Provides functionality to export analysis results in multiple formats:
- PDF: Professional report with charts and findings
- JSON: Data export for other tools and programs
- TXT: Markdown-formatted text report
"""

from typing import TYPE_CHECKING, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import json
import base64
import io

from pages.results_charts import VisualizationEngine

if TYPE_CHECKING:
    from pages.results_model import ResultsDataModel


class ExportEngine:
    """Generates export files in multiple formats."""

    @staticmethod
    def _get_filename(case_name: str, file_hash: str, extension: str) -> str:
        """Generate filename for export.

        Args:
            case_name: Name of the case
            file_hash: SHA256 hash of analyzed file
            extension: File extension (pdf, json, txt)

        Returns:
            Filename with timestamp
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hash_short = file_hash[:8] if file_hash else "unknown"
        safe_case = case_name.replace(" ", "_").replace("/", "_")[:30]
        return f"{safe_case}_{hash_short}_{timestamp}.{extension}"

    @staticmethod
    def _image_to_base64(pil_image) -> Optional[str]:
        """Convert PIL image to base64 string.

        Args:
            pil_image: PIL Image object

        Returns:
            Base64-encoded image string or None
        """
        if not pil_image:
            return None

        try:
            buffer = io.BytesIO()
            pil_image.save(buffer, format="PNG")
            img_bytes = buffer.getvalue()
            return base64.b64encode(img_bytes).decode('utf-8')
        except Exception:
            return None

    @staticmethod
    def export_to_pdf(
        data_model: 'ResultsDataModel',
        output_path: str,
        case_name: str,
        file_hash: str
    ) -> bool:
        """Export results as PDF report.

        Args:
            data_model: ResultsDataModel instance
            output_path: Directory to save PDF
            case_name: Name of the case
            file_hash: SHA256 hash of file

        Returns:
            True if successful, False otherwise
        """
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

            filename = ExportEngine._get_filename(case_name, file_hash, "pdf")
            filepath = Path(output_path) / filename

            # Create PDF
            doc = SimpleDocTemplate(
                str(filepath),
                pagesize=letter,
                rightMargin=0.5 * inch,
                leftMargin=0.5 * inch,
                topMargin=0.75 * inch,
                bottomMargin=0.75 * inch
            )

            elements = []
            styles = getSampleStyleSheet()

            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#0066CC'),
                spaceAfter=12,
                alignment=TA_CENTER
            )
            elements.append(Paragraph("Cryptographic Analysis Report", title_style))
            elements.append(Spacer(1, 0.3 * inch))

            # Metadata
            metadata = data_model.metadata
            meta_data = [
                ["File Name", metadata.file_name or "Unknown"],
                ["File Hash", file_hash[:32] + "..."],
                ["Analysis Date", metadata.analysis_date or "Unknown"],
                ["Case", case_name],
            ]
            meta_table = Table(meta_data, colWidths=[2 * inch, 4 * inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#E8F0F8')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            elements.append(meta_table)
            elements.append(Spacer(1, 0.3 * inch))

            # Statistics Summary
            stats = data_model.get_statistics()
            elements.append(Paragraph("Analysis Summary", styles['Heading2']))

            summary_data = [
                ["Metric", "Value"],
                ["Static Findings", str(stats['static']['total_findings'])],
                ["Average Confidence", f"{stats['static']['average_confidence']:.0%}"],
                ["Finding Types", str(len(stats['static']['by_type']))],
            ]

            if data_model.has_dynamic_results():
                summary_data.extend([
                    ["Dynamic Calls", str(stats['dynamic']['total_calls'])],
                    ["Unique Functions", str(stats['dynamic']['unique_functions'])],
                ])

            summary_table = Table(summary_data, colWidths=[3 * inch, 3 * inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0066CC')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 0.3 * inch))

            # Findings Table
            if data_model.static_findings:
                elements.append(Paragraph("Static Analysis Findings", styles['Heading2']))

                findings_data = [["ID", "Type", "Confidence", "Name"]]
                for finding in data_model.static_findings[:50]:  # Limit to first 50
                    confidence_pct = f"{finding.confidence:.0%}"
                    findings_data.append([
                        finding.id[:12],
                        finding.type[:15],
                        confidence_pct,
                        finding.name[:30]
                    ])

                findings_table = Table(findings_data, colWidths=[1 * inch, 1.5 * inch, 1 * inch, 2.5 * inch])
                findings_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0066CC')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(findings_table)
                elements.append(Spacer(1, 0.2 * inch))

            # Charts
            if data_model.static_findings:
                elements.append(PageBreak())
                elements.append(Paragraph("Analysis Charts", styles['Heading2']))

                # Confidence Histogram
                conf_img = VisualizationEngine.create_confidence_histogram(
                    data_model.static_findings,
                    width=600,
                    height=300
                )
                if conf_img:
                    try:
                        img_buffer = io.BytesIO()
                        conf_img.save(img_buffer, format='PNG')
                        img_buffer.seek(0)
                        img = Image(img_buffer, width=5 * inch, height=2.5 * inch)
                        elements.append(img)
                        elements.append(Spacer(1, 0.2 * inch))
                    except Exception:
                        pass

                # Types Pie Chart
                types_img = VisualizationEngine.create_finding_types_pie(
                    stats,
                    width=600,
                    height=300
                )
                if types_img:
                    try:
                        img_buffer = io.BytesIO()
                        types_img.save(img_buffer, format='PNG')
                        img_buffer.seek(0)
                        img = Image(img_buffer, width=5 * inch, height=2.5 * inch)
                        elements.append(img)
                        elements.append(Spacer(1, 0.2 * inch))
                    except Exception:
                        pass

            # Build PDF
            doc.build(elements)
            return True

        except ImportError:
            # reportlab not installed
            return False
        except Exception as e:
            return False

    @staticmethod
    def export_to_json(
        data_model: 'ResultsDataModel',
        output_path: str,
        case_name: str,
        file_hash: str
    ) -> bool:
        """Export results as JSON.

        Args:
            data_model: ResultsDataModel instance
            output_path: Directory to save JSON
            case_name: Name of the case
            file_hash: SHA256 hash of file

        Returns:
            True if successful, False otherwise
        """
        try:
            filename = ExportEngine._get_filename(case_name, file_hash, "json")
            filepath = Path(output_path) / filename

            # Compile data
            export_data = {
                "export_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "tool": "CryptoScope",
                    "version": "1.0",
                    "case_name": case_name,
                    "file_hash": file_hash,
                },
                "file_metadata": data_model.metadata.to_dict(),
                "statistics": data_model.get_statistics(),
                "static_findings": [f.to_dict() for f in data_model.static_findings],
                "dynamic_calls": [c.to_dict() for c in data_model.dynamic_calls],
            }

            # Add chart images as base64
            charts_data = {}

            # Confidence histogram
            conf_img = VisualizationEngine.create_confidence_histogram(
                data_model.static_findings,
                width=400,
                height=300
            )
            if conf_img:
                charts_data['confidence_histogram'] = ExportEngine._image_to_base64(conf_img)

            # Types pie chart
            types_img = VisualizationEngine.create_finding_types_pie(
                export_data['statistics'],
                width=400,
                height=300
            )
            if types_img:
                charts_data['finding_types_pie'] = ExportEngine._image_to_base64(types_img)

            # Top patterns bar
            patterns_img = VisualizationEngine.create_top_patterns_bar(
                export_data['statistics'],
                width=400,
                height=300
            )
            if patterns_img:
                charts_data['top_patterns_bar'] = ExportEngine._image_to_base64(patterns_img)

            export_data['charts'] = charts_data

            # Write JSON
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)

            return True

        except Exception:
            return False

    @staticmethod
    def export_to_txt(
        data_model: 'ResultsDataModel',
        output_path: str,
        case_name: str,
        file_hash: str
    ) -> bool:
        """Export results as TXT/Markdown report.

        Args:
            data_model: ResultsDataModel instance
            output_path: Directory to save TXT
            case_name: Name of the case
            file_hash: SHA256 hash of file

        Returns:
            True if successful, False otherwise
        """
        try:
            filename = ExportEngine._get_filename(case_name, file_hash, "txt")
            filepath = Path(output_path) / filename

            lines = []

            # Header
            lines.append("# Cryptographic Analysis Report")
            lines.append("")
            lines.append(f"**Case:** {case_name}")
            lines.append(f"**File Hash:** {file_hash}")
            lines.append(f"**Analysis Date:** {data_model.metadata.analysis_date or 'Unknown'}")
            lines.append(f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append("")

            # Summary
            stats = data_model.get_statistics()
            lines.append("## Analysis Summary")
            lines.append("")
            lines.append(f"- **Static Findings:** {stats['static']['total_findings']}")
            lines.append(f"- **Average Confidence:** {stats['static']['average_confidence']:.0%}")
            lines.append(f"- **Finding Types:** {len(stats['static']['by_type'])}")

            if data_model.has_dynamic_results():
                lines.append(f"- **Dynamic Calls:** {stats['dynamic']['total_calls']}")
                lines.append(f"- **Unique Functions:** {stats['dynamic']['unique_functions']}")

            lines.append("")

            # Findings by Type
            lines.append("## Findings by Type")
            lines.append("")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            for ftype, count in sorted(stats['static']['by_type'].items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {ftype} | {count} |")
            lines.append("")

            # Detailed Findings
            if data_model.static_findings:
                lines.append("## Detailed Findings")
                lines.append("")
                lines.append(f"**Total:** {len(data_model.static_findings)} findings")
                lines.append("")

                for i, finding in enumerate(data_model.static_findings[:100], 1):
                    lines.append(f"### Finding {i}: {finding.name}")
                    lines.append(f"- **ID:** {finding.id}")
                    lines.append(f"- **Type:** {finding.type}")
                    lines.append(f"- **Confidence:** {finding.confidence:.0%}")
                    if finding.evidence:
                        lines.append(f"- **Evidence:** {finding.evidence[:100]}...")
                    lines.append("")

                if len(data_model.static_findings) > 100:
                    lines.append(f"*... and {len(data_model.static_findings) - 100} more findings*")
                    lines.append("")

            # Dynamic Analysis
            if data_model.has_dynamic_results() and data_model.dynamic_calls:
                lines.append("## Dynamic Analysis Results")
                lines.append("")

                # Function frequency
                func_calls = {}
                for call in data_model.dynamic_calls:
                    if call.function_name:
                        func_calls[call.function_name] = func_calls.get(call.function_name, 0) + 1

                lines.append("### Most Called Functions")
                lines.append("")
                lines.append("| Function | Calls |")
                lines.append("|----------|-------|")
                for func, count in sorted(func_calls.items(), key=lambda x: x[1], reverse=True)[:20]:
                    lines.append(f"| {func} | {count} |")
                lines.append("")

            # Footer
            lines.append("---")
            lines.append("*Report generated by CryptoScope*")

            # Write file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))

            return True

        except Exception:
            return False
