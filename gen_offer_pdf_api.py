"""
Guven Technology — Commercial Offer PDF Generator (API version)
Called from api.py to generate offer PDFs from database records.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Flowable
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime, timedelta
import os

# ── Fonts ────────────────────────────────────────────────────
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_FONT_CANDIDATES = [
    os.path.join(_SCRIPT_DIR, 'fonts'),           # bundled with project
    '/usr/share/fonts/truetype/dejavu',            # Linux
    '/usr/local/share/fonts/dejavu',               # Linux alt
    os.path.expanduser('~/Library/Fonts'),         # macOS user
    '/Library/Fonts',                              # macOS system
]
FD = _FONT_CANDIDATES[0]  # default to bundled
for _p in _FONT_CANDIDATES:
    if os.path.exists(os.path.join(_p, 'DejaVuSans.ttf')):
        FD = _p
        break

try:
    pdfmetrics.getFont('DV')
except:
    pdfmetrics.registerFont(TTFont('DV',   f'{FD}/DejaVuSans.ttf'))
    pdfmetrics.registerFont(TTFont('DV-B', f'{FD}/DejaVuSans-Bold.ttf'))
    pdfmetrics.registerFont(TTFont('DV-I', f'{FD}/DejaVuSans-Oblique.ttf'))
    pdfmetrics.registerFontFamily('DV', normal='DV', bold='DV-B', italic='DV-I')

# ── Palette ──────────────────────────────────────────────────
NAVY      = colors.HexColor('#0c1a2e')
DARK_BLUE = colors.HexColor('#132d50')
MID_BLUE  = colors.HexColor('#1a4278')
ACCENT    = colors.HexColor('#2a7de1')
SOFT_BLUE = colors.HexColor('#e8f0fe')
FAINT     = colors.HexColor('#f5f8fc')
BORDER    = colors.HexColor('#c8d9ed')
GREEN     = colors.HexColor('#0e8c62')
ORANGE    = colors.HexColor('#c77d14')
VIOLET    = colors.HexColor('#6d3cc7')
GRAY      = colors.HexColor('#5f6d7e')
LGRAY     = colors.HexColor('#9eacbb')
BLACK     = colors.HexColor('#1a2332')
WHITE     = colors.white

W, H = A4
M = 14*mm
CW = W - 2*M

# ── Styles ───────────────────────────────────────────────────
def S(name, f='DV', sz=9, c=BLACK, al=TA_LEFT, ld=None, **kw):
    return ParagraphStyle(name, fontName=f, fontSize=sz, textColor=c,
                          alignment=al, leading=ld or sz*1.45, **kw)

sN  = S('n', sz=8)
sSM = S('sm', sz=6.5, c=GRAY)
sC  = S('c', c=GRAY, al=TA_CENTER)
sOR = S('or', sz=7.5, c=LGRAY, al=TA_RIGHT)
sDI = S('di', f='DV-B', sz=8.5, c=ORANGE, al=TA_CENTER)
sFN = S('fn', f='DV-B', c=GREEN, al=TA_RIGHT)
sCT = S('ct', f='DV-B', sz=8.5, c=WHITE)
sPL = S('pl', f='DV-B', sz=6, c=ACCENT, spaceAfter=0)
sPN = S('pn', f='DV-B', sz=9, c=NAVY)
sPD = S('pd', sz=7, c=GRAY)
sTL = S('tl', sz=8, c=GRAY)
sTV = S('tv', f='DV-B', sz=8, c=BLACK, al=TA_RIGHT)
sGL = S('gl', f='DV-B', sz=10, c=NAVY)
sGV = S('gv', f='DV-B', sz=13, c=ACCENT, al=TA_RIGHT)
sNT = S('nt', f='DV-B', sz=7.5, c=MID_BLUE, spaceAfter=2)
sNN = S('nn', sz=7, c=GRAY, ld=10)

# ── Flowables ────────────────────────────────────────────────
class Header(Flowable):
    def __init__(self, w, offer_number, date_str, valid_str):
        super().__init__()
        self.width = w
        self.height = 22*mm
        self.offer_number = offer_number
        self.date_str = date_str
        self.valid_str = valid_str

    def draw(self):
        c = self.canv
        h = self.height
        c.setFillColor(NAVY)
        c.rect(0, 0, self.width, h, fill=1, stroke=0)
        c.setFillColor(ACCENT)
        c.rect(0, 0, self.width, 0.5, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont('DV-B', 14)
        c.drawString(6*mm, h - 8*mm, 'GUVEN TECHNOLOGY')
        c.setFont('DV', 6.5)
        c.setFillColor(colors.HexColor('#6ea4cf'))
        c.drawString(6*mm, h - 13*mm, 'VÖEN: 1406777811  |  www.gtc.az  |  (+994 12) 504 00 01  |  info@gtc.az')
        c.setFont('DV', 6)
        c.setFillColor(colors.HexColor('#4d8ab5'))
        c.drawString(6*mm, h - 17.5*mm, f'Kommersiya Təklifi  |  Tarix: {self.date_str}  |  Etibarlıdır: {self.valid_str}')
        c.setFillColor(WHITE)
        c.setFont('DV-B', 16)
        c.drawRightString(self.width - 6*mm, h - 9*mm, self.offer_number)
        c.setFont('DV', 7)
        c.setFillColor(colors.HexColor('#6ea4cf'))
        c.drawRightString(self.width - 6*mm, h - 14.5*mm, 'KOMMERSİYA TƏKLİFİ')


class SubTitle(Flowable):
    def __init__(self, w, text):
        super().__init__()
        self.width, self.height, self.text = w, 6*mm, text

    def draw(self):
        c = self.canv
        c.setFillColor(DARK_BLUE)
        c.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        c.setFillColor(ACCENT)
        c.rect(0, 0, 2, self.height, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont('DV-B', 8)
        c.drawString(4*mm, 1.8*mm, self.text)


class Badge(Flowable):
    def __init__(self, text, bg, fg, w=76*mm, h=14*mm):
        super().__init__()
        self.width, self.height = w, h
        self.text, self.bg, self.fg = text, bg, fg

    def draw(self):
        c = self.canv
        c.setFillColor(self.bg)
        c.roundRect(0, 0, self.width, self.height, 3*mm, fill=1, stroke=0)
        c.setFillColor(MID_BLUE)
        c.roundRect(0, 0, 3, self.height, 1.5, fill=1, stroke=0)
        c.setFillColor(self.fg)
        c.setFont('DV-B', 12)
        c.drawCentredString(self.width/2, self.height/2 - 2*mm, self.text)


# ── Currency formatting ──────────────────────────────────────
def cfmt(n, currency='AZN'):
    v = f'{n:,.2f}'
    return f'$ {v}' if currency == 'USD' else f'{v} AZN'

def cfmt_strike(n, currency='AZN'):
    v = f'{n:,.2f}'
    return f'<strike>$ {v}</strike>' if currency == 'USD' else f'<strike>{v} AZN</strike>'


# ── Main generator function ──────────────────────────────────
def generate_offer_pdf(offer, items, out_path):
    """
    Generate a commercial offer PDF.
    offer: dict with offer fields (offer_number, currency, show_vat, vat_pct, client_name, etc.)
    items: list of dicts with (name, category, unit, qty, price, discount, ...)
    out_path: output PDF file path
    """
    currency = offer.get('currency', 'AZN')
    show_vat = bool(offer.get('show_vat', 0))
    vat_pct = offer.get('vat_pct', 18)
    offer_number = offer.get('offer_number', 'GT-OFF-000')

    now = datetime.now()
    date_str = now.strftime('%d.%m.%Y')
    valid_until = offer.get('valid_until', '')
    if valid_until:
        valid_str = valid_until
    else:
        valid_str = (now + timedelta(days=30)).strftime('%d.%m.%Y')

    # Filter out items where line total is zero (price=0 or qty=0)
    items = [it for it in items if ((it.get('price', 0) or 0) * (it.get('qty', 0) or 0)) > 0]

    # Calculations
    orig_total = sum((it.get('qty', 0) or 0) * (it.get('price', 0) or 0) for it in items)
    disc_total_after = sum(
        (it.get('qty', 0) or 0) * (it.get('price', 0) or 0) * (1 - (it.get('discount', 0) or 0) / 100)
        for it in items
    )
    disc_amount = orig_total - disc_total_after
    vat_amt = disc_total_after * vat_pct / 100 if show_vat else 0
    grand = disc_total_after + vat_amt

    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)

    doc = SimpleDocTemplate(out_path, pagesize=A4,
        leftMargin=M, rightMargin=M, topMargin=5*mm, bottomMargin=16*mm)

    story = []

    # Header
    story.append(Header(CW, offer_number, date_str, valid_str))
    story.append(Spacer(1, 3*mm))

    # Parties
    half = CW / 2
    def pbox(label, name, lines):
        return [Paragraph(label, sPL), Paragraph(name, sPN)] + [Paragraph(l, sPD) for l in lines]

    client_name = offer.get('client_name', '') or '—'
    client_voen = offer.get('client_voen', '')
    client_contact = offer.get('client_contact', '')
    client_contract = offer.get('client_contract', '')

    # Auto-fill from company_details.json if client data is missing
    if not client_voen or not client_contact:
        try:
            import json
            cd_path = os.path.join(_SCRIPT_DIR, 'static', 'company_details.json')
            if os.path.exists(cd_path):
                with open(cd_path, 'r', encoding='utf-8') as f:
                    cd_data = json.load(f)
                def _norm(s):
                    return s.lower().replace(' ', '').replace('-', '').replace('«', '').replace('»', '').replace("'", '')
                cn = _norm(client_name)
                matched_info = None
                for code, info in cd_data.items():
                    cl = info.get('client', {})
                    legal = cl.get('legal_name', '')
                    # Match by code OR by legal_name containing the search term
                    if (_norm(code) == cn or
                        cn in _norm(legal) or
                        _norm(code) in cn or
                        _norm(legal.replace('MMC','').replace('ASC','')) == cn):
                        matched_info = info
                        break
                if matched_info:
                    cl = matched_info.get('client', {})
                    if not client_voen and cl.get('voen'):
                        client_voen = cl['voen']
                    if not client_contact and cl.get('director_name'):
                        client_contact = cl['director_name'] + (' — ' + cl['director_title'] if cl.get('director_title') else '')
                    if not client_contract and matched_info.get('contract_number'):
                        client_contract = matched_info['contract_number']
                    if cl.get('legal_name'):
                        client_name = cl['legal_name']
        except Exception:
            pass

    client_lines = []
    if client_voen: client_lines.append(f'VÖEN: {client_voen}')
    if client_contract: client_lines.append(f'Müqavilə: {client_contract}')
    if client_contact: client_lines.append(f'Əlaqədar: {client_contact}')
    if not client_lines: client_lines.append('—')

    ptbl = Table(
        [[pbox('İCRAÇI', '«GUVEN TECHNOLOGY» MMC',
               ['VÖEN: 1406777811',
                'Rzayev Yusif Akif oğlu — Direktoru',
                'Hüseyngulu Sarabski 75, Bakı']),
          pbox('SİFARİŞÇİ', f'«{client_name}»',
               client_lines)]],
        colWidths=[half, half])
    ptbl.setStyle(TableStyle([
        ('BACKGROUND',   (0,0),(0,0), FAINT),
        ('BACKGROUND',   (1,0),(1,0), FAINT),
        ('LINEABOVE',    (0,0),(0,0), 2, MID_BLUE),
        ('LINEABOVE',    (1,0),(1,0), 2, MID_BLUE),
        ('BOX',          (0,0),(0,0), 0.4, BORDER),
        ('BOX',          (1,0),(1,0), 0.4, BORDER),
        ('LEFTPADDING',  (0,0),(-1,-1), 4*mm),
        ('RIGHTPADDING', (0,0),(-1,-1), 4*mm),
        ('TOPPADDING',   (0,0),(-1,-1), 2*mm),
        ('BOTTOMPADDING',(0,0),(-1,-1), 2*mm),
        ('VALIGN',       (0,0),(-1,-1), 'TOP'),
    ]))
    story.append(ptbl)
    story.append(Spacer(1, 3*mm))

    # Section title
    is_equipment = offer.get('offer_type') == 'equipment'
    title = 'Avadanlıq təklifi' if is_equipment else 'Xidmətlərin həcmi və qiymət cədvəli'
    story.append(SubTitle(CW, title))
    story.append(Spacer(1, 2*mm))

    # Table columns
    _c1, _c3, _c4, _c5, _c6, _c7 = 10*mm, 17*mm, 13*mm, 22*mm, 13*mm, 22*mm
    _c2 = CW - _c1 - _c3 - _c4 - _c5 - _c6 - _c7
    col_w = [_c1, _c2, _c3, _c4, _c5, _c6, _c7]

    def hp(t, al=TA_CENTER):
        return Paragraph(t, ParagraphStyle('_h', fontName='DV-B', fontSize=7,
                         textColor=colors.HexColor('#c8d9ed'), alignment=al, leading=9))

    hdr = [hp('#'), hp('Xidmət adı' if not is_equipment else 'Avadanlıq', TA_LEFT),
           hp('Vahid'), hp('Miq.'), hp('İlkin'), hp('End.'), hp('Yekun')]

    rows = [hdr]
    cmds = [
        ('BACKGROUND',    (0,0),(-1,0), NAVY),
        ('LINEBELOW',     (0,0),(-1,0), 0.8, ACCENT),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('TOPPADDING',    (0,0),(-1,0), 2*mm),
        ('BOTTOMPADDING', (0,0),(-1,0), 2*mm),
        ('TOPPADDING',    (0,1),(-1,-1), 1.5*mm),
        ('BOTTOMPADDING', (0,1),(-1,-1), 1.5*mm),
        ('LEFTPADDING',   (0,0),(-1,-1), 1.5*mm),
        ('RIGHTPADDING',  (0,0),(-1,-1), 1.5*mm),
    ]

    prev_cat = None
    cat_rows = []
    ri = 1
    num = 0

    for it in items:
        cat = it.get('category', '')
        qty = it.get('qty', 0) or 0
        price = it.get('price', 0) or 0
        disc = it.get('discount', 0) or 0
        name = it.get('name', '')

        # Category header row
        if cat and cat != prev_cat and not is_equipment:
            cat_rows.append(ri)
            rows.append(['', Paragraph(cat, sCT), '','','','',''])
            ri += 1
            prev_cat = cat

        num += 1
        line_orig = qty * price
        line_fin = line_orig * (1 - disc / 100)

        rows.append([
            Paragraph(str(num), sC),
            Paragraph(name, sN),
            Paragraph(it.get('unit', ''), sSM),
            Paragraph(str(int(qty) if qty == int(qty) else qty), sC),
            Paragraph(cfmt_strike(line_orig, currency) if disc > 0 else cfmt(line_orig, currency),
                      sOR if disc > 0 else sTV),
            Paragraph(f'−{disc}%' if disc > 0 else '—', sDI),
            Paragraph(cfmt(line_fin, currency), sFN),
        ])
        if ri % 2 == 0:
            cmds.append(('BACKGROUND', (0,ri),(-1,ri), FAINT))
        ri += 1

    for ci in cat_rows:
        cmds += [
            ('BACKGROUND', (0,ci),(-1,ci), DARK_BLUE),
            ('SPAN',       (1,ci),(-1,ci)),
            ('TOPPADDING', (0,ci),(-1,ci), 1.5*mm),
            ('BOTTOMPADDING',(0,ci),(-1,ci), 1.5*mm),
        ]

    cmds += [
        ('LINEBELOW', (0,0),(-1,-2), 0.2, colors.HexColor('#dce5ef')),
        ('LINEBELOW', (0,-1),(-1,-1), 0.5, MID_BLUE),
    ]

    tbl = Table(rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle(cmds))
    story.append(tbl)
    story.append(Spacer(1, 3*mm))

    # Totals
    tot_data = [
        [Paragraph('Cəmi (endirimsiz):', sTL), Paragraph(cfmt(orig_total, currency), sTV)],
        [Paragraph('Endirim:', sTL),
         Paragraph(f'− {cfmt(disc_amount, currency)}',
                   S('dv2', f='DV-B', c=ORANGE, al=TA_RIGHT))],
        [Paragraph('Cəmi (endirimli):', sTL),
         Paragraph(cfmt(disc_total_after, currency),
                   S('sv2', f='DV-B', c=MID_BLUE, al=TA_RIGHT))],
    ]
    if show_vat:
        tot_data.append([
            Paragraph(f'ƏDV ({vat_pct}%):', sTL),
            Paragraph(f'+ {cfmt(vat_amt, currency)}',
                      S('vv2', f='DV-B', c=VIOLET, al=TA_RIGHT))
        ])
    tot_data.append([
        Paragraph('YEKUNİ:', sGL),
        Paragraph(cfmt(grand, currency), sGV),
    ])

    ttbl = Table(tot_data, colWidths=[42*mm, 50*mm])
    last = len(tot_data) - 1
    ts = [
        ('BACKGROUND', (0,0),(-1,-1), FAINT),
        ('BOX',        (0,0),(-1,-1), 0.5, BORDER),
        ('LEFTPADDING',(0,0),(-1,-1), 3*mm),
        ('RIGHTPADDING',(0,0),(-1,-1),3*mm),
        ('TOPPADDING', (0,0),(-1,-1), 1.5*mm),
        ('BOTTOMPADDING',(0,0),(-1,-1), 1.5*mm),
        ('VALIGN',     (0,0),(-1,-1), 'MIDDLE'),
        ('LINEABOVE',  (0,last),(-1,last), 1, ACCENT),
        ('BACKGROUND', (0,last),(-1,last), SOFT_BLUE),
        ('TOPPADDING', (0,last),(-1,last), 2.5*mm),
        ('BOTTOMPADDING',(0,last),(-1,last), 2.5*mm),
    ]
    ttbl.setStyle(TableStyle(ts))

    tw = 92*mm
    wrap = Table([[Spacer(1,1), ttbl]], colWidths=[CW - tw, tw])
    wrap.setStyle(TableStyle([('LEFTPADDING',(0,0),(-1,-1),0),
                               ('RIGHTPADDING',(0,0),(-1,-1),0)]))
    story.append(wrap)

    # Savings badge
    if disc_amount > 0:
        badge = Badge(f'Endirim ilə {cfmt(disc_amount, currency)} qənaət edin!',
                      colors.HexColor('#f0f7ff'), MID_BLUE, CW, h=14*mm)
        story.append(Spacer(1, 2.5*mm))
        story.append(badge)

    story.append(Spacer(1, 3*mm))

    # Notes
    notes_text = offer.get('notes', '') or (
        'Bu kommersiya təklifi mövcud müqaviləyə əsasən hazırlanmışdır. '
        'Qiymətlər aylıq xidmət haqqını əks etdirir. Endirimlər yalnız bu təklif '
        'üçün etibarlıdır. ƏDV qiymətlərə ayrıca əlavə olunmuşdur. '
        'Təklif yuxarıda göstərilən tarixədək etibarlıdır.'
    )
    ndata = [
        [Paragraph('Şərtlər və Qeydlər', sNT)],
        [Paragraph(notes_text, sNN)]
    ]
    ntbl = Table(ndata, colWidths=[CW])
    ntbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), colors.HexColor('#f0f7ff')),
        ('BOX',        (0,0),(-1,-1), 0.4, BORDER),
        ('LINEBEFORE', (0,0),(0,-1),  2, MID_BLUE),
        ('LEFTPADDING',(0,0),(-1,-1), 4*mm),
        ('RIGHTPADDING',(0,0),(-1,-1),4*mm),
        ('TOPPADDING', (0,0),(-1,-1), 2.5*mm),
        ('BOTTOMPADDING',(0,0),(-1,-1), 2.5*mm),
    ]))
    story.append(ntbl)

    # Footer
    def draw_footer(c, doc):
        c.saveState()
        c.setFillColor(NAVY)
        c.rect(0, 0, W, 14*mm, fill=1, stroke=0)
        c.setFillColor(ACCENT)
        c.rect(0, 14*mm, W, 0.5, fill=1, stroke=0)
        c.setFont('DV-B', 7.5)
        c.setFillColor(WHITE)
        c.drawString(M, 8*mm, 'Guven Technology MMC')
        c.setFont('DV', 7)
        c.setFillColor(colors.HexColor('#7eadd6'))
        c.drawString(M, 4*mm, 'Hüseyngulu Sarabski 75, Bakı  |  www.gtc.az')
        c.drawRightString(W-M, 8*mm, 'info@gtc.az  |  (+994 12) 504 00 01')
        c.drawRightString(W-M, 4*mm, f'Səhifə {doc.page}')
        c.restoreState()

    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    return out_path
