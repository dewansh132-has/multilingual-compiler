"""
Comprehensive remediation script for all 21 clean demo files.
"""
import glob
import os
import re
import sys

sys.path.insert(0, os.path.abspath('.'))
from web.code_health import analyze_health
from web.compiler_runner import run_pipeline

CLEAN_FILES = [
    'examples/bengali/ecommerce_order_processor.vital',
    'examples/bengali/hospital_patient_registry.vital',
    'examples/bengali/sorting_algorithms_benchmark.vital',
    'examples/english/graph_shortest_path.vital',
    'examples/english/inventory_management_system.vital',
    'examples/english/student_grade_report.vital',
    'examples/fusion/fusion_autonomous_robot.vital',
    'examples/fusion/fusion_data_pipeline.vital',
    'examples/fusion/fusion_stock_exchange.vital',
    'examples/hindi/bank_ledger_system.vital',
    'examples/hindi/library_catalog_system.vital',
    'examples/hindi/matrix_operations_suite.vital',
    'examples/marathi/cryptography_cipher_toolkit.vital',
    'examples/marathi/payroll_tax_calculator.vital',
    'examples/marathi/smart_energy_meter.vital',
    'examples/nepali/financial_investment_portfolio.vital',
    'examples/nepali/flight_reservation_system.vital',
    'examples/nepali/weather_station_analytics.vital',
    'examples/telugu/task_scheduler_engine.vital',
    'examples/telugu/text_statistics_analyzer.vital',
    'examples/telugu/warehouse_logistics_tracker.vital'
]

def remediate_file(fpath, raw):
    text = raw.replace('\r\n', '\n')

    # Specific file cleanups
    if 'graph_shortest_path.vital' in fpath:
        text = text.replace('let total_nodes = 6\n', '')
        text = text.replace('let inf_cost = 99999\n', '')
        text = re.sub(r'if \(total_nodes > 0 and inf_cost > 0\) \{\n\s*print\("([^"]*)"\)\n\}', r'print("\1")', text)

    elif 'student_grade_report.vital' in fpath:
        text = text.replace('let total_students = 5\n', '')
        text = re.sub(r'if \(total_students > 0\) \{\n\s*print\("([^"]*)"\)\n\}', r'print("\1")', text)
        text = text.replace('function process_student_dossier(roll_no, name_code, m, p, c, e) {\n    if (name_code > 0) {\n        let _valid_name = 1\n    }\n', 'function process_student_dossier(roll_no, m, p, c, e) {\n')
        text = re.sub(r'process_student_dossier\((\d+),\s*\d+,\s*', r'process_student_dossier(\1, ', text)

    elif 'inventory_management_system.vital' in fpath:
        text = text.replace('let total_bins = 120\n', '')
        text = text.replace('if (total_bins > 0 and operational_status == 1) {', 'if (operational_status == 1) {')
        text = text.replace('function process_item_stock(item_id, item_name, on_hand, reserved, safety_stock, unit_price) {\n    if (item_id > 0) {\n        let _id_valid = 1\n    }\n', 'function process_item_stock(item_name, on_hand, reserved, safety_stock, unit_price) {\n')
        text = re.sub(r'process_item_stock\(\d+,\s*', 'process_item_stock(', text)
        text = text.replace('function update_bin_location(bin_index, item_code, quantity, max_bin_capacity) {\n    if (item_code != "") {\n        let _code_valid = 1\n    }\n', 'function update_bin_location(bin_index, quantity, max_bin_capacity) {\n')
        text = re.sub(r'update_bin_location\((\d+),\s*"[^"]*",\s*', r'update_bin_location(\1, ', text)

    elif 'fusion_autonomous_robot.vital' in fpath:
        text = text.replace('घ्या चाक_व्यास_सेंमी = 15\n', '')
        text = text.replace('घ्या कमाल_आरपीएम = 120\n', '')
        text = text.replace('    जर (चाक_व्यास_सेंमी > 0 आणि कमाल_आरपीएम > 0) {\n        घ्या _मोटर_मान्य = 1\n    }\n', '')
        text = text.replace('function payload_sample_collector(arm_motor_code, sample_weight_grams) {\n    if (arm_motor_code > 0) {\n        let _arm_ok = 1\n    }\n', 'function payload_sample_collector(sample_weight_grams) {\n')
        text = re.sub(r'payload_sample_collector\(\d+,\s*', 'payload_sample_collector(', text)

    elif 'fusion_data_pipeline.vital' in fpath:
        text = text.replace('let min_record_threshold = 10\n', '')
        text = text.replace('let max_null_tolerance = 5\n', '')
        text = text.replace('    if (min_record_threshold > 0 and max_null_tolerance >= 0) {\n        let _thresh_ok = 1\n    }\n', '')

    elif 'fusion_stock_exchange.vital' in fpath:
        text = text.replace('let compliance_officer_id = 991\n', '')
        text = text.replace('let market_surveillance_active = 1\n', '')
        text = text.replace('घ्या सेटलमेंट_सायकल_दिवस = 2\n', '')
        text = text.replace('    if (compliance_officer_id > 0 and market_surveillance_active == 1) {\n        let _compliance_ok = 1\n    }\n', '')
        text = text.replace('    जर (सेटलमेंट_सायकल_दिवस > 0) {\n        घ्या _दिवस_मान्य = 1\n    }\n', '')

    elif 'weather_station_analytics.vital' in fpath:
        text = text.replace('मान सामान्य_वायुमण्डलीय_चाप = 1013\n', '')
        text = re.sub(r'यदि \(सामान्य_वायुमण्डलीय_चाप > 0\) \{\n\s*छाप\("([^"]*)"\)\n\}', r'छाप("\1")', text)
        text = text.replace(
            'कार्य_गर दैनिक_मौसम_बुलेटिन_जारी_गर(स्टेसन_कोड, औसत_तातो, विन्डचिल, हिउँ_खतरा, बाढी_खतरा) {\n    यदि (औसत_तातो + विन्डचिल > -99999) {\n        मान _मौसम_मान्य = 1\n    }\n',
            'कार्य_गर दैनिक_मौसम_बुलेटिन_जारी_गर(स्टेसन_कोड, हिउँ_खतरा, बाढी_खतरा) {\n'
        )
        text = re.sub(r'दैनिक_मौसम_बुलेटिन_जारी_गर\((\d+),\s*[^,]+,\s*[^,]+,\s*', r'दैनिक_मौसम_बुलेटिन_जारी_गर(\1, ', text)

    elif 'task_scheduler_engine.vital' in fpath:
        text = re.sub(r'    ఒకవేళ \(ప్రాధాన్యత_ర్యాంక్ \+ వేచి_ఉన్న_సమయం > -99999\) \{[^}]*\}\n?', '', text)

    elif 'text_statistics_analyzer.vital' in fpath:
        text = re.sub(r'    ఒకవేళ \(సగటు_పదం \+ సగటు_వాక్యం > -99999\) \{[^}]*\}\n?', '', text)

    # Strip if (> -99999) blocks
    lines = text.splitlines(True)
    res = []
    skip = False
    for l in lines:
        if re.search(r'^\s*(if|यदि|अगर|যদি|जर|ఒకవేళ)\s*\([^)]*>\s*-\s*99999', l):
            skip = True
            continue
        if skip:
            if '}' in l:
                skip = False
            continue
        if re.search(r'^\s*(?:let|मान|मानो|ধরো|घ्या|అనుకో)\s+_\w+\s*=\s*\d+\s*$', l):
            continue
        res.append(l)
    text = ''.join(res)

    # Now detect dead variables and convert to bare calls
    h = analyze_health(text, fpath)
    dead_vars = {it['name'] for it in h.get('dead_code', {}).get('items', []) if it['kind'] == 'unused_variable'}

    var_decl_pat = re.compile(r'^([ \t]*)[^\s=]+\s+([^\s=]+)\s*=\s*(.+)$', re.U)
    new_lines = []
    for line in text.splitlines(True):
        m = var_decl_pat.match(line)
        if m:
            indent = m.group(1)
            vname = m.group(2)
            rhs = m.group(3).strip()
            if vname in dead_vars:
                if '(' in rhs and ')' in rhs:
                    new_lines.append(f"{indent}{rhs}\n")
                    continue
                else:
                    continue
        new_lines.append(line)
    text = ''.join(new_lines)

    return text

def test_remediation():
    all_ok = True
    results = []
    for fpath in CLEAN_FILES:
        with open(fpath, 'r', encoding='utf-8') as fp:
            orig = fp.read()
        res_orig = run_pipeline(orig)
        out_orig = res_orig.get('output', '')
        orig_lines = len(orig.splitlines())

        cleaned = remediate_file(fpath, orig)
        clean_lines = len(cleaned.splitlines())

        res_clean = run_pipeline(cleaned)
        out_clean = res_clean.get('output', '')
        h_clean = analyze_health(cleaned, fpath)
        dead_count = len(h_clean.get('dead_code', {}).get('items', []))

        is_identical = (out_orig == out_clean)
        is_success = res_clean.get('success', False)

        status = "OK" if (dead_count == 0 and is_identical and is_success) else "FAILED"
        if status == "FAILED":
            all_ok = False

        print(f"[{status}] {fpath}: lines {orig_lines} -> {clean_lines}, dead: {dead_count}, identical: {is_identical}, pipe: {is_success}")
        if not is_identical:
            print(f"   Stdout diff length: orig {len(out_orig)} vs clean {len(out_clean)}")
        if not is_success:
            print(f"   Pipeline error: {res_clean.get('status_message')} - {res_clean.get('error_details')}")
        if dead_count > 0:
            for it in h_clean.get('dead_code', {}).get('items', []):
                print(f"   Remaining dead: {it['kind']} {it['name']} line {it['line']}")

        results.append({
            'file': fpath,
            'orig_lines': orig_lines,
            'clean_lines': clean_lines,
            'dead_count': dead_count,
            'identical': is_identical,
            'success': is_success,
            'content': cleaned
        })

    print(f"\nALL 21 CLEAN DEMOS STATUS: {'PASSED (ALL CLEAN)' if all_ok else 'FAILED'}")
    if all_ok:
        for r in results:
            with open(r['file'], 'w', encoding='utf-8') as fp:
                fp.write(r['content'])
        print("Successfully updated all 21 clean demo files on disk!")

if __name__ == '__main__':
    test_remediation()
