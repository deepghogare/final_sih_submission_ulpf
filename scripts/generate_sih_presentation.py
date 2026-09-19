"""
SIH 2026 Presentation Deck Generator for ULPF
Generates a professional 5-slide widescreen PowerPoint presentation (.pptx)
tailored to Smart India Hackathon (NTRO Problem 26156).
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def create_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]  # Blank slide

    # Theme Colors
    BG_COLOR = RGBColor(11, 17, 32)        # #0B1120 Deep Defense Navy
    CARD_BG = RGBColor(30, 41, 59)         # #1E293B Dark Slate Surface
    CARD_BORDER = RGBColor(51, 65, 85)     # #334155 Slate Border
    CYAN = RGBColor(56, 189, 248)          # #38BDF8 Highlight Cyan
    EMERALD = RGBColor(16, 185, 129)       # #10B981 Valid/Tamper-Proof Green
    PURPLE = RGBColor(139, 92, 246)        # #8B5CF6 Modern Violet
    TEXT_WHITE = RGBColor(248, 250, 252)   # #F8FAFC Heading White
    TEXT_MUTED = RGBColor(148, 163, 184)   # #94A3B8 Secondary Grey
    TEXT_BODY = RGBColor(203, 213, 225)    # #CBD5E1 Body Slate
    ACCENT_RED = RGBColor(239, 68, 68)     # #EF4444 Alert Red

    def set_slide_background(slide):
        background = slide.background
        fill = background.fill
        fill.solid()
        fill.fore_color.rgb = BG_COLOR

    def add_header(slide, tag_text, title_text, subtitle_text):
        # Tag pill
        tag_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(8), Inches(0.35))
        tf_tag = tag_box.text_frame
        tf_tag.word_wrap = True
        tf_tag.margin_left = tf_tag.margin_right = tf_tag.margin_top = tf_tag.margin_bottom = 0
        p_tag = tf_tag.paragraphs[0]
        p_tag.text = tag_text.upper()
        p_tag.font.size = Pt(10)
        p_tag.font.bold = True
        p_tag.font.color.rgb = CYAN

        # Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.6))
        tf_title = title_box.text_frame
        tf_title.word_wrap = True
        tf_title.margin_left = tf_title.margin_right = tf_title.margin_top = tf_title.margin_bottom = 0
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.size = Pt(22)
        p_title.font.bold = True
        p_title.font.color.rgb = TEXT_WHITE

        # Subtitle
        sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.3), Inches(11.7), Inches(0.4))
        tf_sub = sub_box.text_frame
        tf_sub.word_wrap = True
        tf_sub.margin_left = tf_sub.margin_right = tf_sub.margin_top = tf_sub.margin_bottom = 0
        p_sub = tf_sub.paragraphs[0]
        p_sub.text = subtitle_text
        p_sub.font.size = Pt(12)
        p_sub.font.color.rgb = TEXT_MUTED

    # =========================================================================
    # SLIDE 1: Title & Overview (The SIH Cover Slide)
    # =========================================================================
    slide1 = prs.slides.add_slide(blank_layout)
    set_slide_background(slide1)

    # Top Tag
    top_tag = slide1.shapes.add_textbox(Inches(1.0), Inches(0.8), Inches(11.3), Inches(0.4))
    tf_tt = top_tag.text_frame
    p_tt = tf_tt.paragraphs[0]
    p_tt.text = "SMART INDIA HACKATHON 2026  |  PROBLEM STATEMENT ID: 26156"
    p_tt.font.size = Pt(11)
    p_tt.font.bold = True
    p_tt.font.color.rgb = CYAN

    # Organisation Badge
    org_box = slide1.shapes.add_textbox(Inches(1.0), Inches(1.2), Inches(11.3), Inches(0.4))
    tf_org = org_box.text_frame
    p_org = tf_org.paragraphs[0]
    p_org.text = "ORGANIZATION: NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO) / MoD"
    p_org.font.size = Pt(12)
    p_org.font.bold = True
    p_org.font.color.rgb = EMERALD

    # Main Project Title
    main_title = slide1.shapes.add_textbox(Inches(1.0), Inches(1.7), Inches(11.3), Inches(1.3))
    tf_mt = main_title.text_frame
    tf_mt.word_wrap = True
    p_mt = tf_mt.paragraphs[0]
    p_mt.text = "UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF)"
    p_mt.font.size = Pt(32)
    p_mt.font.bold = True
    p_mt.font.color.rgb = TEXT_WHITE

    # Subtitle / Vision
    vision_box = slide1.shapes.add_textbox(Inches(1.0), Inches(3.0), Inches(11.3), Inches(0.7))
    tf_vis = vision_box.text_frame
    tf_vis.word_wrap = True
    p_vis = tf_vis.paragraphs[0]
    p_vis.text = "High-Throughput Multi-Vendor Log Normalization with Air-Gapped Cryptographic Blockchain Chain-of-Custody"
    p_vis.font.size = Pt(15)
    p_vis.font.color.rgb = TEXT_BODY

    # 3 Summary Cards at Bottom
    cards_data = [
        ("⚡ HIGH-THROUGHPUT ENGINE", "Multi-worker parallel architecture processing 10,000+ EPS with sub-millisecond parsing latency across thousands of files concurrently.", CYAN),
        ("🛡️ LOSSLESS FORENSIC AUDIT", "Pre-normalization SHA-256 integrity digests with 100% preservation of raw payload, preventing tampering or evidence degradation.", EMERALD),
        ("⛓️ EMBEDDED BLOCKCHAIN LEDGER", "Zero-dependency micro-block chain with O(log N) Merkle Tree selective disclosure proofs for court-admissible audit trails.", PURPLE),
    ]

    card_width = Inches(3.55)
    card_gap = Inches(0.34)
    start_left = Inches(1.0)
    card_top = Inches(4.0)
    card_height = Inches(2.2)

    for i, (head, body, color) in enumerate(cards_data):
        c_left = start_left + i * (card_width + card_gap)
        shape = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c_left, card_top, card_width, card_height)
        shape.fill.solid()
        shape.fill.fore_color.rgb = CARD_BG
        shape.line.color.rgb = color
        shape.line.width = Pt(1.5)

        tb = slide1.shapes.add_textbox(c_left + Inches(0.2), card_top + Inches(0.2), card_width - Inches(0.4), card_height - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True
        p1 = tf.paragraphs[0]
        p1.text = head
        p1.font.size = Pt(12)
        p1.font.bold = True
        p1.font.color.rgb = color
        p1.space_after = Pt(8)

        p2 = tf.add_paragraph()
        p2.text = body
        p2.font.size = Pt(11)
        p2.font.color.rgb = TEXT_BODY

    # Footer
    footer = slide1.shapes.add_textbox(Inches(1.0), Inches(6.6), Inches(11.3), Inches(0.4))
    tf_f = footer.text_frame
    p_f = tf_f.paragraphs[0]
    p_f.text = "SIH 2026 Submission  |  Domain: Cybersecurity & Defense Intelligence  |  Fully Air-Gapped Architecture"
    p_f.font.size = Pt(10)
    p_f.font.color.rgb = TEXT_MUTED

    # =========================================================================
    # SLIDE 2: Problem Statement & Existing Gaps
    # =========================================================================
    slide2 = prs.slides.add_slide(blank_layout)
    set_slide_background(slide2)
    add_header(
        slide2,
        "01 | PROBLEM STATEMENT & DEFENSE CHALLENGES",
        "The Crisis in Enterprise & Defense Security Log Processing",
        "Heterogeneous multi-vendor silos, ingestion bottlenecks, and vulnerable chain-of-custody"
    )

    col_w = Inches(3.64)
    col_gap = Inches(0.35)
    left_start = Inches(0.8)
    top_pos = Inches(1.9)
    col_h = Inches(5.0)

    problem_cards = [
        ("CHALLENGE 1: VENDOR SILOS", "Heterogeneous & Rigid Formats", [
            ("Format Proliferation: ", "Syslog (RFC 3164/5424), CEF, LEEF, JSON, XML, CSV, Snort, and proprietary appliance dumps."),
            ("Brittle Parsing: ", "Hardcoded regex parsers fail on vendor firmware updates, silently dropping critical forensic events."),
            ("Schema Incompatibility: ", "Security analysts waste 60%+ time manually reconciling conflicting vendor schemas during active attacks.")
        ], ACCENT_RED),
        ("CHALLENGE 2: THROUGHPUT LIMITS", "Scalability & Latency Wall", [
            ("Ingestion Bottlenecks: ", "Traditional SIEM pipelines throttle under burst attack volumes (DDoS, automated scanning)."),
            ("Data Loss in Transit: ", "In-memory event drops and lack of deterministic dead-letter quarantine leave defense blind spots."),
            ("Single-Threaded Stalls: ", "Processing thousands of historical log archives takes hours instead of seconds.")
        ], CYAN),
        ("CHALLENGE 3: INTEGRITY VOID", "Zero Chain-of-Custody", [
            ("Insider Threat Vulnerability: ", "Logs stored in standard relational databases or flat files can be altered or erased by compromised admins."),
            ("Court Inadmissibility: ", "Without cryptographic non-repudiation, log evidence is frequently rejected in legal tribunals."),
            ("All-or-Nothing Disclosure: ", "Auditors must inspect entire log stores, violating defense classification and privacy rules.")
        ], PURPLE),
    ]

    for i, (tag, title, bullets, accent) in enumerate(problem_cards):
        c_left = left_start + i * (col_w + col_gap)
        rect = slide2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c_left, top_pos, col_w, col_h)
        rect.fill.solid()
        rect.fill.fore_color.rgb = CARD_BG
        rect.line.color.rgb = CARD_BORDER
        rect.line.width = Pt(1)

        # Top highlight border
        bar = slide2.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, top_pos, col_w, Inches(0.08))
        bar.fill.solid()
        bar.fill.fore_color.rgb = accent
        bar.line.fill.background()

        tb = slide2.shapes.add_textbox(c_left + Inches(0.25), top_pos + Inches(0.2), col_w - Inches(0.5), col_h - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True

        p_tag = tf.paragraphs[0]
        p_tag.text = tag
        p_tag.font.size = Pt(10)
        p_tag.font.bold = True
        p_tag.font.color.rgb = accent
        p_tag.space_after = Pt(2)

        p_t = tf.add_paragraph()
        p_t.text = title
        p_t.font.size = Pt(14)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_WHITE
        p_t.space_after = Pt(12)

        for lead, desc in bullets:
            p_b = tf.add_paragraph()
            p_b.space_after = Pt(10)
            
            run_lead = p_b.add_run()
            run_lead.text = "• " + lead
            run_lead.font.size = Pt(10.5)
            run_lead.font.bold = True
            run_lead.font.color.rgb = TEXT_WHITE
            
            run_desc = p_b.add_run()
            run_desc.text = desc
            run_desc.font.size = Pt(10.5)
            run_desc.font.color.rgb = TEXT_BODY

    # =========================================================================
    # SLIDE 3: Proposed Solution & Core Architecture
    # =========================================================================
    slide3 = prs.slides.add_slide(blank_layout)
    set_slide_background(slide3)
    add_header(
        slide3,
        "02 | PROPOSED SOLUTION & ARCHITECTURE",
        "Universal Log Pre-processing Framework (ULPF) Pipeline",
        "A zero-dependency, parallel multi-stage processing pipeline delivering standardized, forensic-grade events"
    )

    # 4 Pipeline Stage Cards
    stages = [
        ("STAGE 1", "Multi-Worker Ingestion", CYAN, [
            ("High-Concurrency I/O: ", "ThreadPoolExecutor distributes batches of 1,000s of files across CPU cores."),
            ("Content-Based Auto-Detection: ", "Inspects structural signatures & magic tokens without relying on file extensions."),
            ("Multi-Protocol Ingest: ", "FastAPI streaming REST endpoints + CLI batch processors.")
        ]),
        ("STAGE 2", "Lossless SHA-256 Hashing", EMERALD, [
            ("Pre-Parsing Digest: ", "Computes SHA-256 across exact raw event string BEFORE any normalization."),
            ("Cryptographic Fingerprint: ", "Embedded in metadata.raw_event_hash for lifetime forensic non-repudiation."),
            ("Dual Payload Storage: ", "Standardized JSON + original raw payload saved side-by-side.")
        ]),
        ("STAGE 3", "Universal Normalization", PURPLE, [
            ("6-Tier Mapping Engine: ", "Dynamic resolution from explicit rules down to semantic heuristics."),
            ("Canonical Schema: ", "Unified fields for Source, Destination, Network, Device, Threat, User, Action."),
            ("Dynamic Plugin Hooks: ", "Zero-reboot custom parsers & vendor normalization via plugins/.")
        ]),
        ("STAGE 4", "Dual-Store Persistence", CYAN, [
            ("SQLite WAL Mode: ", "High-concurrency non-blocking database writes for instant SOC queries."),
            ("JSONL Archival Stream: ", "Streaming line-delimited records for external SIEM / lakehouse ingest."),
            ("Dead-Letter Quarantine: ", "Failed records stored with diagnostic stack traces; zero dropped events.")
        ]),
    ]

    st_w = Inches(2.7)
    st_gap = Inches(0.24)
    st_left_start = Inches(0.8)
    st_top = Inches(1.9)
    st_h = Inches(4.9)

    for i, (num, st_name, col, items) in enumerate(stages):
        c_left = st_left_start + i * (st_w + st_gap)
        rect = slide3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c_left, st_top, st_w, st_h)
        rect.fill.solid()
        rect.fill.fore_color.rgb = CARD_BG
        rect.line.color.rgb = CARD_BORDER
        rect.line.width = Pt(1)

        # Top Badge
        badge = slide3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c_left + Inches(0.2), st_top + Inches(0.2), Inches(0.9), Inches(0.3))
        badge.fill.solid()
        badge.fill.fore_color.rgb = col
        badge.line.fill.background()
        tf_b = badge.text_frame
        p_b = tf_b.paragraphs[0]
        p_b.text = num
        p_b.font.size = Pt(9)
        p_b.font.bold = True
        p_b.font.color.rgb = BG_COLOR
        p_b.alignment = PP_ALIGN.CENTER

        tb = slide3.shapes.add_textbox(c_left + Inches(0.2), st_top + Inches(0.6), st_w - Inches(0.4), st_h - Inches(0.8))
        tf = tb.text_frame
        tf.word_wrap = True

        p_t = tf.paragraphs[0]
        p_t.text = st_name
        p_t.font.size = Pt(13)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_WHITE
        p_t.space_after = Pt(12)

        for lead, desc in items:
            p_item = tf.add_paragraph()
            p_item.space_after = Pt(8)
            r1 = p_item.add_run()
            r1.text = "• " + lead
            r1.font.size = Pt(10)
            r1.font.bold = True
            r1.font.color.rgb = TEXT_WHITE
            r2 = p_item.add_run()
            r2.text = desc
            r2.font.size = Pt(10)
            r2.font.color.rgb = TEXT_BODY

    # =========================================================================
    # SLIDE 4: Key Innovations & Unique Selling Propositions (USPs)
    # =========================================================================
    slide4 = prs.slides.add_slide(blank_layout)
    set_slide_background(slide4)
    add_header(
        slide4,
        "03 | INNOVATIONS & UNIQUE SELLING PROPOSITIONS",
        "Air-Gapped Blockchain Ledger & Mathematical Chain-of-Custody",
        "Breakthrough features designed for high-assurance defense, intelligence, and forensic integrity"
    )

    # Left Column: 3 Differentiators
    left_col_w = Inches(5.8)
    left_col_x = Inches(0.8)
    innov_top = Inches(1.9)

    innovations = [
        ("⛓️ Embedded Air-Gapped Cryptographic Ledger", 
         "Zero external crypto-tokens, zero gas fees, zero Web3 dependencies. Uses standard SHA-256 micro-block chaining natively inside defense networks. Prevents retroactive deletion or insertion attacks."),
        ("🌲 O(log N) Merkle Tree Selective Disclosure",
         "Binary Merkle tree receipts allow defense agencies to mathematically prove an event's authenticity to a court or auditor WITHOUT disclosing other classified events in the same block."),
        ("🛡️ Live Tamper Simulator & Auto Self-Healing",
         "Built-in evaluator attack simulator demonstrates instant detection when historical blocks are corrupted, plus 1-click self-healing repair recalculating authentic mathematical hashes.")
    ]

    card_h = Inches(1.5)
    card_spacing = Inches(0.2)

    for idx, (title, desc) in enumerate(innovations):
        y_pos = innov_top + idx * (card_h + card_spacing)
        rect = slide4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left_col_x, y_pos, left_col_w, card_h)
        rect.fill.solid()
        rect.fill.fore_color.rgb = CARD_BG
        rect.line.color.rgb = EMERALD if idx == 0 else (PURPLE if idx == 1 else CYAN)
        rect.line.width = Pt(1.2)

        tb = slide4.shapes.add_textbox(left_col_x + Inches(0.2), y_pos + Inches(0.15), left_col_w - Inches(0.4), card_h - Inches(0.3))
        tf = tb.text_frame
        tf.word_wrap = True

        p1 = tf.paragraphs[0]
        p1.text = title
        p1.font.size = Pt(12)
        p1.font.bold = True
        p1.font.color.rgb = TEXT_WHITE
        p1.space_after = Pt(4)

        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(10)
        p2.font.color.rgb = TEXT_BODY

    # Right Column: Screenshot Card of Working Blockchain Ledger
    right_x = Inches(6.9)
    right_w = Inches(5.6)
    right_h = Inches(4.9)

    screen_card = slide4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, right_x, innov_top, right_w, right_h)
    screen_card.fill.solid()
    screen_card.fill.fore_color.rgb = CARD_BG
    screen_card.line.color.rgb = CARD_BORDER
    screen_card.line.width = Pt(1)

    # Header inside right card
    tb_sc = slide4.shapes.add_textbox(right_x + Inches(0.25), innov_top + Inches(0.2), right_w - Inches(0.5), Inches(0.6))
    tf_sc = tb_sc.text_frame
    tf_sc.word_wrap = True
    p_sc1 = tf_sc.paragraphs[0]
    p_sc1.text = "LIVE SYSTEM DEMONSTRATION"
    p_sc1.font.size = Pt(10)
    p_sc1.font.bold = True
    p_sc1.font.color.rgb = CYAN

    p_sc2 = tf_sc.add_paragraph()
    p_sc2.text = "Real-Time Micro-Block Chaining in SIEM Dashboard"
    p_sc2.font.size = Pt(13)
    p_sc2.font.bold = True
    p_sc2.font.color.rgb = TEXT_WHITE

    # Embed User's Real Screenshot of Blockchain Ledger
    screenshot_path = r"C:\Users\deepr\.gemini\antigravity\brain\11ddcb29-bfb1-46c6-8272-7b06b63d571a\.user_uploaded\media_1788554044260.png"
    if os.path.exists(screenshot_path):
        slide4.shapes.add_picture(
            screenshot_path,
            right_x + Inches(0.25),
            innov_top + Inches(0.9),
            width=right_w - Inches(0.5),
            height=Inches(2.1)
        )

    # Caption / Details below screenshot
    tb_desc = slide4.shapes.add_textbox(right_x + Inches(0.25), innov_top + Inches(3.1), right_w - Inches(0.5), Inches(1.6))
    tf_desc = tb_desc.text_frame
    tf_desc.word_wrap = True
    
    p_d1 = tf_desc.paragraphs[0]
    p_d1.text = "• Sequential Hash Linkage: Block #389 'Prev' matches Block #388 'Hash' (b612b3155a...)"
    p_d1.font.size = Pt(10)
    p_d1.font.color.rgb = TEXT_BODY
    p_d1.space_after = Pt(4)

    p_d2 = tf_desc.add_paragraph()
    p_d2.text = "• Micro-Block Batching: Block #388 sealed 7 CEF events with dedicated Merkle Root (23c6e1d75d...)"
    p_d2.font.size = Pt(10)
    p_d2.font.color.rgb = TEXT_BODY
    p_d2.space_after = Pt(4)

    p_d3 = tf_desc.add_paragraph()
    p_d3.text = "• Live Tamper Verification: 100% UNTAMPERED cryptographic health verified via REST & CLI."
    p_d3.font.size = Pt(10)
    p_d3.font.color.rgb = EMERALD

    # =========================================================================
    # SLIDE 5: Technical Feasibility, Validation & National Impact
    # =========================================================================
    slide5 = prs.slides.add_slide(blank_layout)
    set_slide_background(slide5)
    add_header(
        slide5,
        "04 | FEASIBILITY, EMPIRICAL RESULTS & ROADMAP",
        "Production-Grade Performance & National Defense Readiness",
        "Thoroughly tested, fully air-gapped, containerized, and sovereign ready"
    )

    # 3 Summary Cards
    col5_w = Inches(3.64)
    col5_gap = Inches(0.35)
    col5_top = Inches(1.9)
    col5_h = Inches(4.9)

    col5_data = [
        ("VALIDATION & METRICS", "Empirical Test Results", EMERALD, [
            ("60 / 60 Tests Passing: ", "100% coverage across parsers, mapping, normalization, blockchain, and API endpoints."),
            ("Sub-Millisecond Parsing: ", "Average latency of 0.22 - 0.38 ms per event across complex multi-vendor logs."),
            ("High Concurrency: ", "SQLite WAL mode with 30s timeout handles parallel write contention effortlessly."),
            ("Scalable Multi-Threading: ", "CLI process -w 8 processes thousands of files simultaneously.")
        ]),
        ("DEPLOYMENT FEASIBILITY", "Zero-Dependency Air-Gap", CYAN, [
            ("Fully Self-Contained: ", "Docker & Docker Compose deployment with zero external internet dependencies."),
            ("Zero Cloud Egress: ", "100% offline asset enrichment and local SQLite relational query indexing."),
            ("Dynamic Plugin Architecture: ", "Hot-pluggable plugin loader activates custom parsers without restarts."),
            ("CLI & Web Dual Interface: ", "Full terminal headless automation (audit-chain) + rich SOC dashboard.")
        ]),
        ("STRATEGIC IMPACT", "National Security & Sovereignty", PURPLE, [
            ("Vendor Lock-In Eliminated: ", "Replaces expensive proprietary foreign SIEM ingestion layers (Splunk, QRadar)."),
            ("Court-Admissible Evidence: ", "Provides mathematical chain-of-custody for Indian Cyber Law tribunals."),
            ("Cross-Agency Defense Interop: ", "Unified schema links tri-services, NTRO, CERT-In, and LEA forensics."),
            ("Future Roadmap: ", "Hardware Security Module (HSM) root signing, FPGA line-rate hardware acceleration.")
        ]),
    ]

    for i, (tag, title, col, bullets) in enumerate(col5_data):
        c_left = left_start + i * (col5_w + col5_gap)
        rect = slide5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c_left, col5_top, col5_w, col5_h)
        rect.fill.solid()
        rect.fill.fore_color.rgb = CARD_BG
        rect.line.color.rgb = CARD_BORDER
        rect.line.width = Pt(1)

        # Top bar
        bar = slide5.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, col5_top, col5_w, Inches(0.08))
        bar.fill.solid()
        bar.fill.fore_color.rgb = col
        bar.line.fill.background()

        tb = slide5.shapes.add_textbox(c_left + Inches(0.25), col5_top + Inches(0.2), col5_w - Inches(0.5), col5_h - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True

        p_tag = tf.paragraphs[0]
        p_tag.text = tag
        p_tag.font.size = Pt(10)
        p_tag.font.bold = True
        p_tag.font.color.rgb = col
        p_tag.space_after = Pt(2)

        p_t = tf.add_paragraph()
        p_t.text = title
        p_t.font.size = Pt(14)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_WHITE
        p_t.space_after = Pt(12)

        for lead, desc in bullets:
            p_b = tf.add_paragraph()
            p_b.space_after = Pt(8)
            r1 = p_b.add_run()
            r1.text = "• " + lead
            r1.font.size = Pt(10)
            r1.font.bold = True
            r1.font.color.rgb = TEXT_WHITE
            r2 = p_b.add_run()
            r2.text = desc
            r2.font.size = Pt(10)
            r2.font.color.rgb = TEXT_BODY

    output_path = "ULPF_SIH2026_Presentation.pptx"
    prs.save(output_path)
    print(f"[+] Presentation successfully created at: {output_path}")

if __name__ == "__main__":
    create_presentation()
