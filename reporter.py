import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_vapt_pdf(target_ip, scan_data):
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    pdf_filename = f"{target_ip}_NetVigil_VAPT_Report.pdf"
    pdf_path = os.path.join(reports_dir, pdf_filename)
    
    doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=12
    )
    story.append(Paragraph("NetVigil VAPT Assessment Report", title_style))
    story.append(Paragraph(f"Target IP: <b>{target_ip}</b>", styles['Normal']))
    story.append(Spacer(1, 12))
    
    findings_table_data = [["Port", "Service", "Severity", "Issue Details & Remediation"]]
    
    for finding in scan_data.get("findings", []):
        port_text = str(finding.get('port'))
        service_text = str(finding.get('service'))
        severity_text = f"<b>{finding.get('risk')}</b>"
        details_text = f"<b>Risk:</b> {finding.get('issue')}<br/><b>Remediation:</b> {finding.get('recommendation')}"
        
        findings_table_data.append([
            Paragraph(port_text, styles['Normal']),
            Paragraph(service_text, styles['Normal']),
            Paragraph(severity_text, styles['Normal']),
            Paragraph(details_text, styles['Normal'])
        ])
        
    findings_table = Table(findings_table_data, colWidths=[45, 90, 85, 310])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CBD5E1')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold')
    ]))
    
    story.append(findings_table)
    doc.build(story)
    return pdf_path
