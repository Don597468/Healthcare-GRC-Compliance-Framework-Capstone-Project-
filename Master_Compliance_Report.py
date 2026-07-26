"""
GRC Compliance Master Report Generator

This script reads raw evidence from Active Directory, Microsoft Intune, a server
inventory export, and vendor/supply-chain records, evaluates each
against the project's control matrix (Domains 1-5), and produces a
single Excel workbook with:

  1. Access Control             (Domain 1)
  2. Device Compliance          (Domains 2 & 5)
  3. Vendor & Incident Response (Domains 3 & 4)
  4. Vendor Risk Summary        (Aggregate score + risk rating per vendor(Including the Internal - Hospital IT (Unmanaged) vendor))

Inputs (same folder as this script):
  Access_Control_Users.csv
  Device_Compliance_Inventory.csv
  server_inventory.csv
  Vendor_Supply_Chain_and_Incident_Respone_Report.csv

Output:
  GRC_Compliance_Report.xlsx
"""

import math
import re
from collections import defaultdict
from datetime import date

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

TODAY = date(2026, 7, 27)

AD_FILE = "Access_Control_Users.csv"
DEVICE_FILE = "Device_Compliance_Inventory.csv"
SERVER_FILE = "server_inventory.csv"
VENDOR_FILE = "Vendor_Supply_Chain_and_Incident_Respone_Report.csv"
OUTPUT_FILE = "GRC_Compliance_Report.xlsx"

FONT_NAME = "Aptos Narrow"
FONT_SIZE = 14

SHEET_COLORS = {
    "Access Control": "1F4E78",
    "Device Compliance": "145A32",
    "Vendor & Incident Response": "6C3483",
    "Vendor Risk Summary": "922B21",
}

CONTROL_WEIGHTS = {
    "AC-1": -15, "AC-2": -15, "AC-3": -10,
    "DP-1": -15, "DP-2": -15, "DP-3": -10,
    "IR-1": -15, "IR-2": -15, "IR-3": -5,
    "VR-1": -15, "VR-2": -10, "VR-3": -10,
    "OT-1": -15, "OT-2": -15, "OT-3": -15,
}

DEVICE_NOTES = {
    "RAD-LAPTOP01": {
        "device_type": "IT", "vendor": "SparkNet IT Services Ltd.",
        "dp1_note": "BitLocker disabled",
        "dp3_applicable": False, "dp3_pass": None,
    },
    "EHR-NURSE-WKS01": {
        "device_type": "IT", "vendor": "ReCloud Systems Inc.",
        "dp1_note": "BitLocker enabled",
        "dp3_applicable": False, "dp3_pass": None,
    },
    "BED-TAB01": {
        "device_type": "OT (Clinical)", "vendor": "Zark Device Corp.",
        "dp1_note": "BitLocker enabled",
        "dp3_applicable": False, "dp3_pass": None,
    },
    "BEN-PC": {
        "device_type": "IT", "vendor": "ReCloud Systems Inc.",
        "dp1_note": "N/A - Windows Home N cannot support BitLocker",
        "dp3_applicable": True, "dp3_pass": False,
        "dp3_note": "No documented compensating control for encryption-incapable device",
    },
    "StevenOlele_AndroidForWork_7/22/2026_2:04 PM": {
        "device_type": "OT (Clinical)", "vendor": "Zark Device Corp.",
        "dp1_note": "Storage encryption enabled by default (Android 17)",
        "dp3_applicable": False, "dp3_pass": None,
    },
    "StevenOlele_AndroidForWork_7/22/2026_1:32 PM": {
        "device_type": "OT (Clinical)", "vendor": "Zark Device Corp.",
        "dp1_note": "Storage encryption enabled by default (Android 14)",
        "dp3_applicable": False, "dp3_pass": None,
    },
}

CONTROL_ID_PATTERN = re.compile(r"\b([A-Z]{2}-\d)\s+FAIL\b")

# A vendor can only be held accountable for assets it actually manages.
# The domain controller is internal hospital infrastructure (no vendor
# manages it), and BEN-PC is a Personal-ownership BYOD device outside
# any managed-service contract -- both still appear honestly in the
# Device Compliance sheet, but neither counts against a vendor's score.
RISK_ATTRIBUTION_OVERRIDE = {
    "EHR-DATABASE-SERVER": "Internal - Hospital IT (Unmanaged)",
    "BEN-PC": "Internal - Hospital IT (Unmanaged)",
}


def build_access_control_rows():
    df = pd.read_csv(AD_FILE)
    rows = []
    for _, user in df.iterrows():
        findings = []

        if str(user["SHARED_LOGIN"]).strip() == "Yes":
            findings.append("AC-1 FAIL: shared account, not unique per person")

        if str(user["REMOTE_MFA_ENABLED"]).strip() == "No":
            findings.append("AC-2 FAIL: MFA not enabled")

        review_date = pd.to_datetime(user["LAST_ACCESS_REVIEW_DATE"]).date()
        days_since_review = (TODAY - review_date).days
        if days_since_review > 90:
            findings.append(f"AC-3 FAIL: last reviewed {days_since_review} days ago (limit 90)")

        rows.append({
            "User ID": user["USER_ID"],
            "Name": user["NAME"],
            "Role": user["ROLE"],
            "Vendor": user["VENDOR"],
            "Last Access Review": review_date.strftime("%Y-%m-%d"),
            "Issues Found": len(findings),
            "Details": "; ".join(findings) if findings else "No issues",
            "Status": "NON-COMPLIANT" if findings else "COMPLIANT",
        })
    return rows


def build_device_compliance_rows():
    rows = []

    intune_df = pd.read_csv(DEVICE_FILE)
    for _, row in intune_df.iterrows():
        name = row["DeviceName"]
        notes = DEVICE_NOTES.get(name, {})
        findings = []

        if row["ComplianceState_loc"] == "Not compliant":
            if "Android" in str(row["OS_loc"]):
                findings.append(f"OT-2 FAIL: below minimum required OS version ({row['OSVersion']})")
            else:
                findings.append(f"DP-1 FAIL: {notes.get('dp1_note', 'policy violation')}")

        if notes.get("dp3_applicable") and notes.get("dp3_pass") is False:
            findings.append(f"DP-3 FAIL: {notes.get('dp3_note', 'no compensating control documented')}")

        rows.append({
            "Device Name": name,
            "Device Type": notes.get("device_type", "Unknown"),
            "Vendor": notes.get("vendor", "Unknown"),
            "OS": row["OS_loc"],
            "OS Version": row["OSVersion"],
            "Ownership": row["OwnerType_loc"],
            "Issues Found": len(findings),
            "Details": "; ".join(findings) if findings else "No issues",
            "Status": "NON-COMPLIANT" if findings else "COMPLIANT",
        })

    server_df = pd.read_csv(SERVER_FILE)
    for _, srv in server_df.iterrows():
        findings = []
        if str(srv["ENCRYPTION_ENABLED"]).startswith("No"):
            findings.append(f"DP-1 FAIL: {srv['ENCRYPTION_ENABLED']}")

        patch_date = pd.to_datetime(srv["LAST_PATCH_DATE"]).date()
        days_since_patch = (TODAY - patch_date).days
        if days_since_patch > 90:
            findings.append(f"OT-2 FAIL: last patched {days_since_patch} days ago (limit 90)")

        if str(srv["IN_INVENTORY"]).strip() != "Yes":
            findings.append("OT-1 FAIL: not in formal inventory")

        rows.append({
            "Device Name": srv["DEVICE_NAME"],
            "Device Type": srv["DEVICE_TYPE"],
            "Vendor": srv["VENDOR"],
            "OS": "Windows Server",
            "OS Version": "N/A",
            "Ownership": "Company",
            "Issues Found": len(findings),
            "Details": "; ".join(findings) if findings else "No issues",
            "Status": "NON-COMPLIANT" if findings else "COMPLIANT",
        })
    return rows


def build_vendor_rows():
    df = pd.read_csv(VENDOR_FILE)
    rows = []
    for _, vendor in df.iterrows():
        findings = []

        if str(vendor["SIGNED_BAA"]).strip() == "No":
            findings.append("VR-1 FAIL: no signed BAA on file")

        ra_date = vendor["LAST_RISK_ASSESSMENT_DATE"]
        if pd.isna(ra_date):
            findings.append("VR-2 FAIL: no risk assessment on record")
            ra_display = "None on record"
        else:
            ra_date = pd.to_datetime(ra_date).date()
            days_since_ra = (TODAY - ra_date).days
            if days_since_ra > 365:
                findings.append(f"VR-2 FAIL: risk assessment {days_since_ra} days old (limit 365)")
            ra_display = ra_date.strftime("%Y-%m-%d")

        if str(vendor["SUBPROCESSOR_PLAN_DOCUMENTED"]).strip() == "No":
            findings.append("VR-3 FAIL: no documented sub-processor risk plan")

        if str(vendor["IR_PLAN_EXISTS"]).strip() == "No":
            findings.append("IR-1 FAIL: no incident response plan on file")
        else:
            tested_date = pd.to_datetime(vendor["IR_PLAN_LAST_TESTED_DATE"]).date()
            days_since_test = (TODAY - tested_date).days
            if days_since_test > 365:
                findings.append(f"IR-1 FAIL: IR plan last tested {days_since_test} days ago (limit 365)")

        if vendor["BREACH_NOTIFICATION_DAYS"] > 60:
            findings.append(
                f"IR-2 FAIL: breach notification takes {vendor['BREACH_NOTIFICATION_DAYS']} days (limit 60)"
            )

        if vendor["INCIDENT_LOG_RETENTION_MONTHS"] < 24:
            findings.append(
                f"IR-3 FAIL: logs retained {vendor['INCIDENT_LOG_RETENTION_MONTHS']} months (limit 24)"
            )

        rows.append({
            "Vendor ID": vendor["VENDOR_ID"],
            "Vendor Name": vendor["VENDOR_NAME"],
            "Vendor Type": vendor["VENDOR_TYPE"],
            "BAA Signed": vendor["SIGNED_BAA"],
            "Last Risk Assessment": ra_display,
            "Issues Found": len(findings),
            "Details": "; ".join(findings) if findings else "No issues",
            "Status": "NON-COMPLIANT" if findings else "COMPLIANT",
        })
    return rows


def risk_rating(score):
    if score >= -10:
        return "LOW"
    if score >= -50:
        return "MEDIUM"
    return "HIGH"


def build_vendor_risk_rows(ac_rows, device_rows, vendor_rows):
    gaps_by_vendor = defaultdict(set)
    all_vendors = set()

    for row in ac_rows:
        vendor = row["Vendor"]
        all_vendors.add(vendor)
        gaps_by_vendor[vendor].update(CONTROL_ID_PATTERN.findall(row["Details"]))

    for row in device_rows:
        vendor = RISK_ATTRIBUTION_OVERRIDE.get(row["Device Name"], row["Vendor"])
        all_vendors.add(vendor)
        gaps_by_vendor[vendor].update(CONTROL_ID_PATTERN.findall(row["Details"]))

    for row in vendor_rows:
        vendor = row["Vendor Name"]
        all_vendors.add(vendor)
        gaps_by_vendor[vendor].update(CONTROL_ID_PATTERN.findall(row["Details"]))

    rows = []
    for vendor in sorted(all_vendors):
        gaps = sorted(gaps_by_vendor[vendor])
        score = sum(CONTROL_WEIGHTS.get(control, 0) for control in gaps)
        rows.append({
            "Vendor Name": vendor,
            "Control Gaps": ", ".join(gaps) if gaps else "None",
            "Aggregate Score": score,
            "Risk Rating": risk_rating(score),
        })
    return rows


def style_sheet(ws, header_color):
    header_font = Font(bold=True, color="FFFFFF", name=FONT_NAME, size=FONT_SIZE)
    header_fill = PatternFill("solid", start_color=header_color)
    header_align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    center = Alignment(horizontal="center", vertical="center", wrap_text=False)
    left_nowrap = Alignment(horizontal="left", vertical="center", wrap_text=False)
    left_wrap = Alignment(horizontal="left", vertical="center", wrap_text=True)
    thin = Side(style="thin", color="B0B0B0")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    green_fill = PatternFill("solid", start_color="C6EFCE")
    green_font = Font(color="006100", name=FONT_NAME, size=FONT_SIZE)
    red_fill = PatternFill("solid", start_color="FFC7CE")
    red_font = Font(color="9C0006", name=FONT_NAME, size=FONT_SIZE)
    yellow_fill = PatternFill("solid", start_color="FFEB9C")
    yellow_font = Font(color="9C6500", name=FONT_NAME, size=FONT_SIZE)
    body_font = Font(name=FONT_NAME, size=FONT_SIZE)

    for cell in ws[1]:
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_align
        cell.border = border
    ws.row_dimensions[1].height = 34

    headers = [c.value for c in ws[1]]
    wrap_column = "Details" if "Details" in headers else None
    status_column = "Status" if "Status" in headers else None
    rating_column = "Risk Rating" if "Risk Rating" in headers else None

    char_width_factor = 1.25
    wrap_column_width = 90

    for col_idx, header in enumerate(headers, start=1):
        col_letter = get_column_letter(col_idx)
        if header == wrap_column:
            ws.column_dimensions[col_letter].width = wrap_column_width
            continue
        longest = len(str(header))
        for row in ws.iter_rows(min_row=2, max_row=ws.max_row, min_col=col_idx, max_col=col_idx):
            cell_len = len(str(row[0].value)) if row[0].value is not None else 0
            longest = max(longest, cell_len)
        ws.column_dimensions[col_letter].width = longest * char_width_factor + 4

    chars_per_line = 62
    line_height = 24

    for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
        for cell in row:
            cell.font = body_font
            cell.border = border
            cell.alignment = left_nowrap

        max_lines = 1

        if wrap_column:
            wrap_cell = row[headers.index(wrap_column)]
            wrap_cell.alignment = left_wrap
            max_lines = max(max_lines, math.ceil(len(str(wrap_cell.value or "")) / chars_per_line))

        if status_column:
            status_cell = row[headers.index(status_column)]
            status_cell.alignment = center
            if status_cell.value == "COMPLIANT":
                status_cell.fill = green_fill
                status_cell.font = green_font
            elif status_cell.value == "NON-COMPLIANT":
                status_cell.fill = red_fill
                status_cell.font = red_font

        if rating_column:
            rating_cell = row[headers.index(rating_column)]
            rating_cell.alignment = center
            if rating_cell.value == "LOW":
                rating_cell.fill = green_fill
                rating_cell.font = green_font
            elif rating_cell.value == "MEDIUM":
                rating_cell.fill = yellow_fill
                rating_cell.font = yellow_font
            elif rating_cell.value == "HIGH":
                rating_cell.fill = red_fill
                rating_cell.font = red_font

        ws.row_dimensions[row[0].row].height = max(26, max_lines * line_height)

    ws.auto_filter.ref = ws.dimensions
    ws.freeze_panes = "A2"


def write_sheet(wb, sheet_name, rows):
    ws = wb.create_sheet(sheet_name)
    df = pd.DataFrame(rows)
    ws.append(list(df.columns))
    for row in df.itertuples(index=False):
        ws.append(list(row))
    style_sheet(ws, SHEET_COLORS[sheet_name])
    return df


def main():
    wb = Workbook()
    wb.remove(wb.active)

    ac_rows = build_access_control_rows()
    device_rows = build_device_compliance_rows()
    vendor_rows = build_vendor_rows()
    risk_rows = build_vendor_risk_rows(ac_rows, device_rows, vendor_rows)

    write_sheet(wb, "Access Control", ac_rows)
    write_sheet(wb, "Device Compliance", device_rows)
    write_sheet(wb, "Vendor & Incident Response", vendor_rows)
    write_sheet(wb, "Vendor Risk Summary", risk_rows)

    wb.save(OUTPUT_FILE)

    print(f"Report saved to {OUTPUT_FILE}")
    for row in risk_rows:
        print(f"  {row['Vendor Name']}: score {row['Aggregate Score']}, Risk Profile {row['Risk Rating']}")


if __name__ == "__main__":
    main()
