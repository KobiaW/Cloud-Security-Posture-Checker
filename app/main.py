"""
Cloud Security Posture Checker
Author: Kobia Williams
Description: Analyzes AWS IAM policies and config files for security misconfigurations.
"""

import json
import re
import gradio as gr
from app.checks import run_all_checks
from app.report import generate_report


def analyze_config(file_obj, raw_text):
    """
    Entry point for the Gradio interface.
    Accepts either an uploaded file or pasted JSON/YAML text.
    Returns a formatted HTML report.
    """
    content = None

    if file_obj is not None:
        try:
            with open(file_obj.name, "r") as f:
                content = f.read()
        except Exception as e:
            return f"<p style='color:red;'>❌ Error reading file: {e}</p>", "", ""

    elif raw_text and raw_text.strip():
        content = raw_text.strip()

    else:
        return (
            "<p style='color:orange;'>⚠️ Please upload a file or paste config content.</p>",
            "",
            "",
        )

    # Parse JSON
    try:
        config = json.loads(content)
    except json.JSONDecodeError as e:
        return (
            f"<p style='color:red;'>❌ Invalid JSON: {e}</p>",
            "",
            "",
        )

    # Run all security checks
    findings = run_all_checks(config)

    # Generate report sections
    summary_html, details_html, remediation_html = generate_report(findings)

    return summary_html, details_html, remediation_html


def load_sample(sample_name):
    """Load a sample config for demo purposes."""
    samples = {
        "Misconfigured IAM Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Principal": "*"
                }
            ]
        }, indent=2),
        "Open S3 Bucket Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }, indent=2),
        "Secure Policy (Clean)": json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-secure-bucket/reports/*",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/ReportReader"},
                    "Condition": {
                        "Bool": {"aws:MultiFactorAuthPresent": "true"}
                    }
                }
            ]
        }, indent=2),
        "No MFA + Wildcard Actions": json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:*", "ec2:*", "s3:*"],
                    "Resource": "*",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/devuser"}
                }
            ]
        }, indent=2),
    }
    return samples.get(sample_name, "")


CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap');

:root {
    --bg: #0a0e1a;
    --surface: #111827;
    --border: #1e2d45;
    --accent: #00d4ff;
    --accent2: #ff6b35;
    --text: #e2e8f0;
    --muted: #64748b;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --info: #3b82f6;
}

body, .gradio-container {
    background: var(--bg) !important;
    font-family: 'Syne', sans-serif !important;
    color: var(--text) !important;
}

h1, h2, h3 { font-family: 'Syne', sans-serif !important; }

.gr-box, .gr-panel, .gr-form {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
}

button.primary {
    background: linear-gradient(135deg, #00d4ff, #0080ff) !important;
    border: none !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 600 !important;
    letter-spacing: 0.05em !important;
}
"""


def build_ui():
    with gr.Blocks(css=CSS, title="Cloud Security Posture Checker") as demo:

        gr.HTML("""
        <div style="text-align:center; padding: 2rem 0 1rem;">
            <div style="font-family:'JetBrains Mono',monospace; color:#00d4ff; font-size:0.75rem; letter-spacing:0.2em; margin-bottom:0.5rem;">
                CLOUD SECURITY POSTURE CHECKER
            </div>
            <h1 style="font-family:'Syne',sans-serif; font-size:2.5rem; font-weight:800; color:#e2e8f0; margin:0;">
                AWS Config <span style="color:#00d4ff;">Analyzer</span>
            </h1>
            <p style="color:#64748b; margin-top:0.75rem; font-size:0.95rem;">
                Detect misconfigurations in IAM policies, S3 bucket policies, and AWS config files.
            </p>
        </div>
        """)

        with gr.Row():
            with gr.Column(scale=1):
                gr.HTML('<div style="font-family:\'JetBrains Mono\',monospace; color:#00d4ff; font-size:0.7rem; letter-spacing:0.15em; margin-bottom:0.5rem;">INPUT</div>')

                file_input = gr.File(
                    label="Upload JSON Config / Policy File",
                    file_types=[".json"],
                )

                gr.HTML('<div style="text-align:center; color:#64748b; margin:0.5rem 0; font-size:0.85rem;">— or paste below —</div>')

                text_input = gr.Code(
                    label="Paste JSON Content",
                    language="json",
                    lines=12,
                )

                with gr.Row():
                    sample_dropdown = gr.Dropdown(
                        choices=[
                            "Misconfigured IAM Policy",
                            "Open S3 Bucket Policy",
                            "Secure Policy (Clean)",
                            "No MFA + Wildcard Actions",
                        ],
                        label="Load Sample Config",
                        value=None,
                    )
                    load_btn = gr.Button("Load", size="sm")

                analyze_btn = gr.Button("🔍 Analyze Config", variant="primary", size="lg")
                clear_btn = gr.Button("Clear", size="sm")

            with gr.Column(scale=2):
                gr.HTML('<div style="font-family:\'JetBrains Mono\',monospace; color:#00d4ff; font-size:0.7rem; letter-spacing:0.15em; margin-bottom:0.5rem;">RESULTS</div>')

                with gr.Tabs():
                    with gr.Tab("📊 Summary"):
                        summary_out = gr.HTML(label="Summary")

                    with gr.Tab("🔎 Findings"):
                        details_out = gr.HTML(label="Detailed Findings")

                    with gr.Tab("🛠 Remediation"):
                        remediation_out = gr.HTML(label="Remediation Steps")

        # Wire events
        analyze_btn.click(
            fn=analyze_config,
            inputs=[file_input, text_input],
            outputs=[summary_out, details_out, remediation_out],
        )

        load_btn.click(
            fn=load_sample,
            inputs=[sample_dropdown],
            outputs=[text_input],
        )

        clear_btn.click(
            fn=lambda: (None, "", "", "", ""),
            inputs=[],
            outputs=[file_input, text_input, summary_out, details_out, remediation_out],
        )

        gr.HTML("""
        <div style="text-align:center; padding:1.5rem 0 0.5rem; color:#64748b; font-size:0.8rem; font-family:'JetBrains Mono',monospace;">
            Built by Kobia Williams · Cloud Security Portfolio Project · 
            <a href="https://github.com/kobiawilliams/cloud-posture-checker" 
               style="color:#00d4ff; text-decoration:none;">GitHub</a>
        </div>
        """)

    return demo


if __name__ == "__main__":
    app = build_ui()
    app.launch(share=False)
