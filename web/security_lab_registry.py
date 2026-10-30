# -*- coding: utf-8 -*-
"""
web/security_lab_registry.py — Centralized Registry for Multilingual Security Lab Demos

Defines comprehensive test expectations and educational metadata for all 24
Security Lab programs across 6 supported languages:
  - English
  - Hindi
  - Telugu
  - Bengali
  - Marathi
  - Nepali

Each demo provides:
  - Unique demo ID
  - Display name and supported language
  - Difficulty level
  - Scenario description
  - Relative file path and intentionally faulty code
  - Expected defect categories
  - Expected findings with source line ranges
  - Expected behavior after correction
  - Safe test inputs
  - Secure reference fix description and remediated code
  - Expected blocked compiler stages (if syntax error present)
"""

import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class ExpectedFinding:
    rule_id: str
    title: str
    severity: str           # "Critical", "High", "Medium", "Low", "Informational"
    defect_type: str        # "security", "syntax", "semantic", "logic", "lexical"
    line: Optional[int]
    description: str


@dataclass
class SecurityLabDemo:
    id: str
    title: str
    language: str
    scenario_type: str      # "Demo A", "Demo B", "Demo C", "Demo D"
    difficulty: str         # "Beginner", "Intermediate", "Advanced"
    relative_path: str
    description: str
    defect_categories: List[str]
    expected_findings: List[ExpectedFinding]
    expected_post_fix_behavior: str
    safe_test_inputs: Dict[str, Any]
    reference_fix_description: str
    reference_fix_code: str
    blocked_stages_expected: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["expected_findings"] = [asdict(f) for f in self.expected_findings]
        return d


# ---------------------------------------------------------------------------
# DEMO REGISTRY DEFINITION
# ---------------------------------------------------------------------------

SECURITY_LAB_DEMOS: List[SecurityLabDemo] = [
    # =========================================================================
    # ENGLISH DEMOS (4)
    # =========================================================================
    SecurityLabDemo(
        id="SEC-DEMO-EN-01",
        title="Vulnerable Account & Permission Management",
        language="English",
        scenario_type="Demo A",
        difficulty="Intermediate",
        relative_path="examples/security_lab/english/sec_auth_account.vital",
        description="Banking and authorization service verifying session presence but missing object-level ownership checks (IDOR) and containing undefined symbol references.",
        defect_categories=["security", "logic", "semantic"],
        expected_findings=[
            ExpectedFinding("SEC-AUTH-001", "Broken Object-Level Authorization (IDOR)", "Critical", "security", 38, "Caller ID is authenticated but never verified against source account owner."),
            ExpectedFinding("SEC-AUTH-003", "Suspension Check Bypass for Small Transfers", "High", "logic", 43, "Allows suspended accounts to transfer funds if amount <= 500."),
            ExpectedFinding("SEC-SEM-001", "Undefined Variable 'acc_status'", "Medium", "semantic", 67, "Variable 'acc_status' is referenced before declaration.")
        ],
        expected_post_fix_behavior="Transfers require caller to equal from_account_id, status check enforced for all amounts, and valid variable names.",
        safe_test_inputs={"caller_id": 1042, "from_account": 1042, "to_account": 5001, "amount": 250},
        reference_fix_description="Add ownership assertion `if (caller_id != from_account_id) return 0`, enforce status check unconditionally, and fix variable name to `account_closed`.",
        reference_fix_code="""// Remediated Account & Permission Management
let current_session_user = 1042
let current_session_token = "sess_live_token_77a9b"
let is_authenticated = 1

function verify_session(token) {
    if (token == "sess_live_token_77a9b") {
        return 1
    } else {
        return 0
    }
}

function check_account_status(account_id, is_active) {
    if (is_active == 0) {
        print("Warning: Account is currently suspended.")
        return 0
    }
    return 1
}

function transfer_funds(caller_id, from_account_id, to_account_id, amount) {
    let auth_ok = verify_session(current_session_token)
    if (auth_ok == 0) {
        print("Access Denied: Invalid Session Token.")
        return 0
    }

    // Fixed IDOR: Assert ownership
    if (caller_id != from_account_id) {
        print("Access Denied: Caller does not own the source account.")
        return 0
    }

    let status_ok = check_account_status(from_account_id, 1)
    if (status_ok == 0) {
        print("Transfer blocked: Source account is suspended.")
        return 0
    }

    print("Initiating transfer amount:")
    print(amount)
    print("Funds transferred successfully to:")
    print(to_account_id)
    return 1
}

print("=== Secure Account Manager ===")
let target_acc = 5001
let result = transfer_funds(current_session_user, current_session_user, target_acc, 250)
print("Transfer status code:")
print(result)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-EN-02",
        title="Unsafe Data Processing & Configuration",
        language="English",
        scenario_type="Demo B",
        difficulty="Intermediate",
        relative_path="examples/security_lab/english/sec_data_config.vital",
        description="Configuration loader storing raw API keys in source code, lacking upper boundary validation, and leaking credentials into debug logs.",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-DATA-001", "Hardcoded Production Secret Key in Source Code", "High", "security", 8, "Embedded production secret token 'sk_live_sec_prod...'."),
            ExpectedFinding("SEC-DATA-002", "Sensitive Information Disclosure via Debug Logs", "Medium", "security", 34, "Internal debug logger prints secret key to output."),
            ExpectedFinding("SEC-DATA-003", "Off-by-One Upper Bound Vulnerability", "Low", "logic", 21, "Bound check allows out-of-range index 5 for 5-element array.")
        ],
        expected_post_fix_behavior="Secrets loaded securely or masked, bounds strictly limited to index < 5, and debug logs redacted.",
        safe_test_inputs={"record_index": 2, "user_role": "analyst"},
        reference_fix_description="Replace hardcoded secret with runtime configuration lookup, restrict indices to [0, 4], and mask debug outputs.",
        reference_fix_code="""// Remediated Data Processing & Configuration
let admin_secret_key = "REDACTED_USE_ENVIRONMENT_CONFIG"
let debug_mode_enabled = 0

function read_config_record(record_index, user_role) {
    if (record_index < 0) {
        print("Error: Negative index rejected.")
        return 0
    }
    if (record_index >= 5) {
        print("Error: Index out of bounds (0-4).")
        return 0
    }
    let record_value = 100 + (record_index * 25)
    return record_value
}

let config_val = read_config_record(2, "guest_operator")
print("Returned configuration value:")
print(config_val)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-EN-03",
        title="Injection & Unsafe Execution Patterns",
        language="English",
        scenario_type="Demo C",
        difficulty="Advanced",
        relative_path="examples/security_lab/english/sec_injection_eval.vital",
        description="Dynamic database and system command interface with taint flow from unvalidated input to dynamic SQL and shell command evaluation sinks.",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-INJ-001", "Simulated SQL Injection via Unchecked Concatenation", "High", "security", 20, "User-controlled filter directly concatenated into query."),
            ExpectedFinding("SEC-LEX-004", "Shell Command Chaining Sequence Detected (';')", "Critical", "security", 31, "Shell command string contains unquoted semicolon metacharacter."),
            ExpectedFinding("SEC-IR-001", "Dynamic Code Evaluation via 'eval()'", "Critical", "security", 37, "Direct invocation of eval() executes arbitrary strings.")
        ],
        expected_post_fix_behavior="Queries parameterized, shell commands replaced with structured interfaces, and eval() removed completely.",
        safe_test_inputs={"filter": "status=1", "command_arg": "health_check"},
        reference_fix_description="Parameterize database lookups, eliminate shell command formatting, and delete dangerous eval() calls.",
        reference_fix_code="""// Remediated Safe Execution Harness
function execute_safe_query(filter_id) {
    print("Executing parameterized safe query for account ID:")
    print(filter_id)
    return 1
}

function dispatch_safe_task(task_name) {
    print("Dispatching safe registered task:")
    print(task_name)
    return 1
}

print("=== Secure Safe Execution Harness ===")
let query_status = execute_safe_query(1042)
let task_status = dispatch_safe_task("diagnostics")
print("All tasks executed safely.")
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-EN-04",
        title="Complex Business Workflow with Multiple Defects",
        language="English",
        scenario_type="Demo D",
        difficulty="Advanced",
        relative_path="examples/security_lab/english/sec_business_workflow.vital",
        description="Multi-tier e-commerce pricing engine containing missing delimiter syntax error, business logic negative quantity vulnerability, and unvalidated discount flow.",
        defect_categories=["syntax", "logic", "security"],
        expected_findings=[
            ExpectedFinding("SEC-PAR-001", "Unbalanced Block Scope Delimiters ('{' vs '}')", "Medium", "syntax", 42, "Missing closing brace '}' on negative invoice validation block."),
            ExpectedFinding("SEC-LOGIC-001", "Missing Negative Item Quantity Check (Refund Exploit)", "High", "logic", 19, "Allows negative quantity to create negative invoice balance.")
        ],
        expected_post_fix_behavior="Closes syntax block, prevents negative quantities (returns error), and calculates correct positive invoice total.",
        safe_test_inputs={"price": 100, "quantity": 2, "coupon": "VIP_DISCOUNT_50"},
        reference_fix_description="Add closing brace '}' to balance syntax tree and add validation `if (item_quantity <= 0) return 0`.",
        reference_fix_code="""// Remediated Business Workflow
let tax_rate = 18
let merchant_id = 9021

function validate_coupon_code(coupon_code) {
    if (coupon_code == "VIP_DISCOUNT_50") {
        return 50
    } elif (coupon_code == "SPRING_SAVINGS_20") {
        return 20
    } else {
        return 0
    }
}

function calculate_item_subtotal(unit_price, item_quantity) {
    if (item_quantity <= 0) {
        print("Error: Quantity must be positive.")
        return 0
    }
    let raw_subtotal = unit_price * item_quantity
    return raw_subtotal
}

function process_order_items(base_price, quantity, coupon_code) {
    let subtotal = calculate_item_subtotal(base_price, quantity)
    if (subtotal == 0) {
        return 0
    }
    let discount_percent = validate_coupon_code(coupon_code)
    let discount_amount = (subtotal * discount_percent) / 100
    let discounted_subtotal = subtotal - discount_amount
    let total_tax = (discounted_subtotal * tax_rate) / 100
    let final_invoice_amount = discounted_subtotal + total_tax
    return final_invoice_amount
}

print("=== Secure E-Commerce Workflow ===")
let final_order = process_order_items(100, 2, "VIP_DISCOUNT_50")
print("Order finalized with total:")
print(final_order)
""",
        blocked_stages_expected=["ast_construction", "semantic_analysis", "symbol_table", "ir_generation", "code_generation", "code_validation", "sandbox_execution"]
    ),

    # =========================================================================
    # HINDI DEMOS (4)
    # =========================================================================
    SecurityLabDemo(
        id="SEC-DEMO-HI-01",
        title="खाता और अनुमति प्रबंधन (Account & Permission Management)",
        language="Hindi",
        scenario_type="Demo A",
        difficulty="Intermediate",
        relative_path="examples/security_lab/hindi/sec_auth_account_hi.vital",
        description="बैंकिंग और प्राधिकरण सेवा जिसमें सत्र उपस्थिति की पुष्टि होती है किंतु ऑब्जेक्ट-स्तरीय स्वामित्व की कमी (IDOR) है।",
        defect_categories=["security", "logic", "semantic"],
        expected_findings=[
            ExpectedFinding("SEC-AUTH-001", "टूटा हुआ ऑब्जेक्ट-स्तरीय प्राधिकरण (IDOR)", "Critical", "security", 36, "कॉलर आईडी स्रोत खाते का स्वामी है या नहीं यह सत्यापित नहीं किया गया।"),
            ExpectedFinding("SEC-AUTH-003", "छोटी राशि के लिए खाता निलंबन बाईपास", "High", "logic", 41, "५०० से कम राशि के लिए निलंबित खाते से स्थानांतरण की अनुमति।"),
            ExpectedFinding("SEC-SEM-001", "अपरिभाषित चर 'खाता_अंतिम_स्थिति'", "Medium", "semantic", 65, "चर 'खाता_अंतिम_स्थिति' घोषणा से पहले संदर्भित है।")
        ],
        expected_post_fix_behavior="स्थानांतरण के लिए कॉलर_आईडी और स्रोत_खाता समान होना आवश्यक है और निलंबन जांच सभी राशियों पर लागू होती है।",
        safe_test_inputs={"caller_id": 1042, "from_account": 1042, "to_account": 5001, "amount": 250},
        reference_fix_description="स्वामित्व सत्यापन जोड़ें और अपरिभाषित चर नाम को ठीक करें।",
        reference_fix_code="""टिप्पणी सुरक्षित खाता प्रबंधन
मानो वर्तमान_सत्र_उपयोगकर्ता = 1042
मानो वर्तमान_सत्र_टोकन = "sess_live_token_77a9b"

कार्य सत्र_सत्यापित_करें(टोकन) {
    अगर (टोकन == "sess_live_token_77a9b") {
        लौटाओ 1
    } अन्यथा {
        लौटाओ 0
    }
}

कार्य राशि_स्थानांतरित_करें(कॉलर_आईडी, स्रोत_खाता, लक्ष्य_खाता, राशि) {
    मानो सत्र_ठीक = सत्र_सत्यापित_करें(वर्तमान_सत्र_टोकन)
    अगर (सत्र_ठीक == 0) {
        लौटाओ 0
    }
    अगर (कॉलर_आईडी != स्रोत_खाता) {
        लौटाओ 0
    }
    लौटाओ 1
}

मानो परिणाम = राशि_स्थानांतरित_करें(वर्तमान_सत्र_उपयोगकर्ता, वर्तमान_सत्र_उपयोगकर्ता, 5001, 250)
लिखो(परिणाम)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-HI-02",
        title="असुरक्षित डेटा और विन्यास प्रसंस्करण (Unsafe Data & Config Processing)",
        language="Hindi",
        scenario_type="Demo B",
        difficulty="Intermediate",
        relative_path="examples/security_lab/hindi/sec_data_config_hi.vital",
        description="स्रोत कोड में हार्डकोडेड मास्टर गुप्त कुंजी, अनुपलब्ध ऊपरी सीमा जांच, और आंतरिक डीबग लॉग में क्रेडेंशियल प्रकटीकरण।",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-DATA-001", "हार्डकोडेड गुप्त कुंजी स्रोत कोड में मौजूद", "High", "security", 8, "एम्बेडेड उत्पादन गुप्त कुंजी 'sk_live_sec_prod...'."),
            ExpectedFinding("SEC-DATA-002", "डीबग लॉग के माध्यम से संवेदनशील डेटा प्रकटीकरण", "Medium", "security", 34, "आंतरिक डीबग लॉगर कंसोल में गुप्त कुंजी प्रिंट करता है।"),
            ExpectedFinding("SEC-DATA-003", "ऑफ-बाई-वन सीमा त्रुटि", "Low", "logic", 21, "सीमा जांच 5-तत्व बफर के लिए अमान्य इंडेक्स 5 की अनुमति देती है।")
        ],
        expected_post_fix_behavior="गुप्त कुंजी सुरक्षित या मास्क की जाती है, सीमाएं सूचकांक < ५ तक सीमित होती हैं।",
        safe_test_inputs={"record_index": 2, "role": "operator"},
        reference_fix_description="हार्डकोडेड गुप्त कुंजी को हटाएं, सूचकांक सीमाएं ० से ४ तक सीमित करें।",
        reference_fix_code="""टिप्पणी सुरक्षित विन्यास संसाधक
मानो डीबग_मोड_सक्रिय = 0

कार्य विन्यास_रिकॉर्ड_पढ़ें(रिकॉर्ड_क्रमांक, उपयोगकर्ता_भूमिका) {
    अगर (रिकॉर्ड_क्रमांक < 0) {
        लौटाओ 0
    }
    अगर (रिकॉर्ड_क्रमांक >= 5) {
        लौटाओ 0
    }
    मानो रिकॉर्ड_मान = 100 + (रिकॉर्ड_क्रमांक * 25)
    लौटाओ रिकॉर्ड_मान
}

मानो विन्यास_मान = विन्यास_रिकॉर्ड_पढ़ें(2, "ऑपरेटर")
लिखो(विन्यास_मान)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-HI-03",
        title="इंजेक्शन और असुरक्षित निष्पादन पैटर्न (Injection & Unsafe Execution)",
        language="Hindi",
        scenario_type="Demo C",
        difficulty="Advanced",
        relative_path="examples/security_lab/hindi/sec_injection_eval_hi.vital",
        description="गतिशील डेटाबेस और सिस्टम कमांड इंटरफ़ेस जिसमें उपयोगकर्ता इनपुट से गतिशील SQL और शेल कमांड तक अनियंत्रित प्रवाह होता है।",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-INJ-001", "अप्रतिबंधित स्ट्रिंग संयोजन के माध्यम से SQL इंजेक्शन", "High", "security", 20, "उपयोगकर्ता इनपुट सीधे क्वेरी में संयोजित होता है।"),
            ExpectedFinding("SEC-LEX-004", "शेल कमांड चेनिंग अनुक्रम (';')", "Critical", "security", 31, "शेल कमांड स्ट्रिंग में अनकोटेड अर्धविराम शामिल है।"),
            ExpectedFinding("SEC-IR-001", "गतिशील कोड मूल्यांकन सिंक (eval)", "Critical", "security", 37, "डायनामिक eval() कॉल मनमाना कोड चलाता है।")
        ],
        expected_post_fix_behavior="क्वेरी मान मानकीकृत किए जाते हैं, शेल कमांड हटाए जाते हैं और eval() को पूरी तरह समाप्त किया जाता है।",
        safe_test_inputs={"filter": "status=1", "cmd": "check"},
        reference_fix_description="डेटाबेस लुकअप को पैरामीटराइज़ करें और खतरनाक eval() कॉलों को हटाएं।",
        reference_fix_code="""टिप्पणी सुरक्षित निष्पादन परीक्षण
कार्य सुरक्षित_क्वेरी_चलाएं(खाता_आईडी) {
    लिखो("पैरामीटराइज्ड सुरक्षित क्वेरी:")
    लिखो(खाता_आईडी)
    लौटाओ 1
}

मानो स्थिति = सुरक्षित_क्वेरी_चलाएं(1042)
लिखो(स्थिति)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-HI-04",
        title="जटिल व्यावसायिक वर्कफ़्लो (Complex Business Workflow)",
        language="Hindi",
        scenario_type="Demo D",
        difficulty="Advanced",
        relative_path="examples/security_lab/hindi/sec_business_workflow_hi.vital",
        description="बहु-स्तरीय ई-कॉमर्स मूल्य निर्धारण इंजन जिसमें कोष्ठक असंतुलन सिंटैक्स त्रुटि और नकारात्मक मात्रा की व्यावसायिक तर्क त्रुटि शामिल है।",
        defect_categories=["syntax", "logic", "security"],
        expected_findings=[
            ExpectedFinding("SEC-PAR-001", "असंतुलित ब्लॉक स्कोप डिलीमीटर ('{' बनाम '}')", "Medium", "syntax", 42, "नकारात्मक चालान ब्लॉक पर अंतिम कोष्ठक '}' छूट गया है।"),
            ExpectedFinding("SEC-LOGIC-001", "ऋणात्मक वस्तु मात्रा जांच का अभाव (रिफंड शोषण)", "High", "logic", 19, "ऋणात्मक मात्रा से ऋणात्मक बीजक राशि बनती है।")
        ],
        expected_post_fix_behavior="सिंटैक्स ब्लॉक संतुलित होता है, नकारात्मक मात्रा को अस्वीकार किया जाता है और चालान कुल सही गणना करता है।",
        safe_test_inputs={"price": 100, "quantity": 2, "coupon": "VIP_DISCOUNT_50"},
        reference_fix_description="ब्लॉक को बंद करने के लिए '}' जोड़ें और मात्रा <= 0 की वैधता जांचें।",
        reference_fix_code="""टिप्पणी सुरक्षित ई-कॉमर्स वर्कफ़्लो
मानो कर_दर = 18

कार्य कूपन_सत्यापित_करें(कूपन_कोड) {
    अगर (कूपन_कोड == "VIP_DISCOUNT_50") {
        लौटाओ 50
    } अन्यथा {
        लौटाओ 0
    }
}

कार्य वस्तु_उपयोग_गणना(इकाई_मूल्य, मात्रा) {
    अगर (मात्रा <= 0) {
        लौटाओ 0
    }
    लौटाओ इकाई_मूल्य * मात्रा
}

कार्य आदेश_संसाधित_करें(मूल_मूल्य, मात्रा, कूपन) {
    मानो उप_योग = वस्तु_उपयोग_गणना(मूल_मूल्य, मात्रा)
    अगर (उप_योग == 0) {
        लौटाओ 0
    }
    मानो छूट_प्रतिशत = कूपन_सत्यापित_करें(कूपन)
    मानो छूट_राशि = (उप_योग * छूट_प्रतिशत) / 100
    मानो छूट_के_बाद = उप_योग - छूट_राशि
    मानो कुल_कर = (छूट_के_बाद * कर_दर) / 100
    मानो अंतिम_चालान_राशि = छूट_के_बाद + कुल_कर
    लौटाओ अंतिम_चालान_राशि
}

मानो अंतिम_आदेश = आदेश_संसाधित_करें(100, 2, "VIP_DISCOUNT_50")
लिखो(अंतिम_आदेश)
""",
        blocked_stages_expected=["ast_construction", "semantic_analysis", "symbol_table", "ir_generation", "code_generation", "code_validation", "sandbox_execution"]
    ),

    # =========================================================================
    # TELUGU DEMOS (4)
    # =========================================================================
    SecurityLabDemo(
        id="SEC-DEMO-TE-01",
        title="ఖాతా మరియు అనుమతుల నిర్వహణ (Account & Permission Management)",
        language="Telugu",
        scenario_type="Demo A",
        difficulty="Intermediate",
        relative_path="examples/security_lab/telugu/sec_auth_account_te.vital",
        description="సెషన్ ఉనికిని తనిఖీ చేసే బ్యాంకింగ్ మరియు ఆథరైజేషన్ సర్వీస్ కానీ ఆబ్జెక్ట్-స్థాయి యాజమాన్య తనిఖీలను (IDOR) కోల్పోయింది.",
        defect_categories=["security", "logic", "semantic"],
        expected_findings=[
            ExpectedFinding("SEC-AUTH-001", "విచ్ఛిన్నమైన ఆబ్జెక్ట్-స్థాయి ప్రామాణీకరణ (IDOR)", "Critical", "security", 36, "కాలర్ ఐడి మూల ఖాతా యజమానా కాదా అని ఎప్పుడూ ధృవీకరించబడదు."),
            ExpectedFinding("SEC-AUTH-003", "చిన్న బదిలీలకు సస్పెన్షన్ తనిఖీ బైపాస్", "High", "logic", 41, "మొత్తం <= 500 అయితే సస్పెండ్ చేయబడిన ఖాతాల నుండి బదిలీలను అనుమతిస్తుంది."),
            ExpectedFinding("SEC-SEM-001", "నిర్వచించని వేరియబుల్ 'ఖాతా_ముగింపు_స్థితి'", "Medium", "semantic", 65, "వేరియబుల్ 'ఖాతా_ముగింపు_స్థితి' డిక్లరేషన్‌కు ముందే ఉపయోగించబడింది.")
        ],
        expected_post_fix_behavior="బదిలీలకు కాలర్ మూల ఖాతా సమానంగా ఉండాలి మరియు సస్పెన్షన్ తనిఖీ అన్ని మొత్తాలకు వర్తిస్తుంది.",
        safe_test_inputs={"caller_id": 1042, "from_account": 1042, "to_account": 5001, "amount": 250},
        reference_fix_description="యాజమాన్య ధృవీకరణను జోడించండి మరియు వేరియబుల్ పేరును సరిచేయండి.",
        reference_fix_code="""వ్యాఖ్య సురక్షిత ఖాతా నిర్వహణ
అనుకో ప్రస్తుత_సెషన్_వినియోగదారుడు = 1042
అనుకో ప్రస్తుత_సెషన్_టోకెన్ = "sess_live_token_77a9b"

ఫంక్షన్ సెషన్_ధృవీకరించు(టోకెన్) {
    ఒకవేళ (టోకెన్ == "sess_live_token_77a9b") {
        తిరిగి_ఇవ్వు 1
    } కాకపోతే {
        తిరిగి_ఇవ్వు 0
    }
}

ఫంక్షన్ నిధులు_బదిలీ_చేయి(కాలర్_ఐడి, మూల_ఖాతా, లక్ష్య_ఖాతా, మొత్తం) {
    అనుకో సెషన్_సరి = సెషన్_ధృవీకరించు(ప్రస్తుత_సెషన్_టోకెన్)
    ఒకవేళ (సెషన్_సరి == 0) {
        తిరిగి_ఇవ్వు 0
    }
    ఒకవేళ (కాలర్_ఐడి != మూల_ఖాతా) {
        తిరిగి_ఇవ్వు 0
    }
    తిరిగి_ఇవ్వు 1
}

అనుకో ఫలితం = నిధులు_బదిలీ_చేయి(ప్రస్తుత_సెషన్_వినియోగదారుడు, ప్రస్తుత_సెషన్_వినియోగదారుడు, 5001, 250)
ముద్రించు(ఫలితం)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-TE-02",
        title="అసురక్షిత డేటా మరియు కాన్ఫిగరేషన్ (Unsafe Data & Config Processing)",
        language="Telugu",
        scenario_type="Demo B",
        difficulty="Intermediate",
        relative_path="examples/security_lab/telugu/sec_data_config_te.vital",
        description="సోర్స్ కోడ్‌లో హార్డ్‌కోడ్ చేసిన సీక్రెట్ కీ, ఎగువ సరిహద్దు ధ్రువీకరణ లేకపోవడం మరియు డీబగ్ లాగ్‌లలో సమాచార బహిర్గతం.",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-DATA-001", "సోర్స్ కోడ్‌లో హార్డ్‌కోడ్ చేసిన మాస్టర్ సీక్రెట్ కీ", "High", "security", 8, "ఎంబెడెడ్ సీక్రెట్ కీ 'sk_live_sec_prod...'."),
            ExpectedFinding("SEC-DATA-002", "డీబగ్ లాగ్‌ల ద్వారా సున్నితమైన సమాచార బహిర్గతం", "Medium", "security", 34, "అంతర్గత డీబగ్ లాగర్ కన్సోల్‌లో రహస్య కీని ప్రింట్ చేస్తుంది."),
            ExpectedFinding("SEC-DATA-003", "ఆఫ్-బై-వన్ ఎగువ సరిహద్దు దుర్బలత్వం", "Low", "logic", 21, "5-మూలకాల బఫర్ కోసం చెల్లని సూచిక 5ను అనుమతిస్తుంది.")
        ],
        expected_post_fix_behavior="రహస్యాలు సురక్షితంగా లోడ్ చేయబడతాయి, సూచిక పరిమితి < 5 వరకు కఠినంగా ఉంటుంది.",
        safe_test_inputs={"record_index": 2, "role": "operator"},
        reference_fix_description="హార్డ్‌కోడ్ చేసిన కీని తీసివేసి సూచిక సరిహద్దులను 0 నుండి 4 వరకు పరిమితం చేయండి.",
        reference_fix_code="""వ్యాఖ్య సురక్షిత కాన్ఫిగరేషన్ ప్రాసెసర్
అనుకో డీబగ్_మోడ్_సక్రియం = 0

ఫంక్షన్ కాన్ఫిగరేషన్_రికార్డ్_చదువు(రికార్డ్_సూచిక, వినియోగదారు_పాత్ర) {
    ఒకవేళ (రికార్డ్_సూచిక < 0) {
        తిరిగి_ఇవ్వు 0
    }
    ఒకవేళ (రికార్డ్_సూచిక >= 5) {
        తిరిగి_ఇవ్వు 0
    }
    అనుకో రికార్డ్_విలువ = 100 + (రికార్డ్_సూచిక * 25)
    తిరిగి_ఇవ్వు రికార్డ్_విలువ
}

అనుకో కాన్ఫిగ్_విలువ = కాన్ఫిగరేషన్_రికార్డ్_చదువు(2, "ఆపరేటర్")
ముద్రించు(కాన్ఫిగ్_విలువ)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-TE-03",
        title="ఇంజెక్షన్ మరియు అసురక్షిత అమలు నమూనాలు (Injection & Unsafe Execution)",
        language="Telugu",
        scenario_type="Demo C",
        difficulty="Advanced",
        relative_path="examples/security_lab/telugu/sec_injection_eval_te.vital",
        description="వినియోగదారు ఇన్‌పుట్ నుండి డైనమిక్ SQL మరియు షెల్ కమాండ్ సింక్‌ల వరకు అపరిమిత ప్రవాహం.",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-INJ-001", "స్ట్రింగ్ కలయిక ద్వారా SQL ఇంజెక్షన్", "High", "security", 20, "వినియోగదారు ఇన్‌పుట్ నేరుగా క్వెరీలో కలుపబడుతుంది."),
            ExpectedFinding("SEC-LEX-004", "షెల్ కమాండ్ చైనింగ్ సీక్వెన్స్ (';')", "Critical", "security", 31, "షెల్ కమాండ్ స్ట్రింగ్‌లో సెమికోలన్ ఉంటుంది."),
            ExpectedFinding("SEC-IR-001", "డైనమిక్ కోడ్ మూల్యాంకన సింక్ (eval)", "Critical", "security", 37, "డైనమిక్ eval() కాల్ యాదృచ్ఛిక కోడ్‌ను అమలు చేస్తుంది.")
        ],
        expected_post_fix_behavior="క్వెరీలు పారామీటరైజ్ చేయబడతాయి, షెల్ కమాండ్‌లు తీసివేయబడతాయి మరియు eval() రద్దు చేయబడుతుంది.",
        safe_test_inputs={"filter": "status=1", "cmd": "check"},
        reference_fix_description="డేటాబేస్ లుకప్‌లను పారామీటరైజ్ చేయండి మరియు ప్రమాదకరమైన eval() కాల్‌లను తొలగించండి.",
        reference_fix_code="""వ్యాఖ్య సురక్షిత అమలు హార్నెస్
ఫంక్షన్ సురక్షిత_క్వెరీ_రన్_చేయి(ఖాతా_ఐడి) {
    ముద్రించు("సురక్షితమైన పారామీటరైజ్డ్ క్వెరీ:")
    ముద్రించు(ఖాతా_ఐడి)
    తిరిగి_ఇవ్వు 1
}

అనుకో స్థితి = సురక్షిత_క్వెరీ_రన్_చేయి(1042)
ముద్రించు(స్థితి)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-TE-04",
        title="సంక్లిష్ట వ్యాపార వర్క్‌ఫ్లో (Complex Business Workflow)",
        language="Telugu",
        scenario_type="Demo D",
        difficulty="Advanced",
        relative_path="examples/security_lab/telugu/sec_business_workflow_te.vital",
        description="బ్రాకెట్ అసమతుల్యత సింటాక్స్ లోపం మరియు ప్రతికూల పరిమాణ వ్యాపార తర్కం లోపంతో కూడిన ఇ-కామర్స్ ఆర్డర్ ఇంజిన్.",
        defect_categories=["syntax", "logic", "security"],
        expected_findings=[
            ExpectedFinding("SEC-PAR-001", "అసమతుల్య బ్లాక్ స్కోప్ డీలిమిటర్లు ('{' vs '}')", "Medium", "syntax", 42, "ప్రతికూల ఇన్వాయిస్ బ్లాక్‌పై ముగింపు బ్రాకెట్ '}' తప్పిపోయింది."),
            ExpectedFinding("SEC-LOGIC-001", "ప్రతికూల పరిమాణం తనిఖీ లేకపోవడం (రీఫండ్ దోపిడీ)", "High", "logic", 19, "ప్రతికూల పరిమాణం ప్రతికూల ఇన్వాయిస్ మొత్తాన్ని సృష్టిస్తుంది.")
        ],
        expected_post_fix_behavior="సింటాక్స్ బ్లాక్‌ను మూసివేస్తుంది, ప్రతికూల పరిమాణాలను తిరస్కరిస్తుంది మరియు సరైన ఇన్వాయిస్ మొత్తాన్ని లెక్కిస్తుంది.",
        safe_test_inputs={"price": 100, "quantity": 2, "coupon": "VIP_DISCOUNT_50"},
        reference_fix_description="బ్లాక్‌ను ముగించడానికి '}' జోడించండి మరియు పరిమాణం <= 0 ను తనిఖీ చేయండి.",
        reference_fix_code="""వ్యాఖ్య సురక్షిత ఇ-కామర్స్ వర్క్‌ఫ్లో
అనుకో పన్ను_రేటు = 18

ఫంక్షన్ కూపన్_ధృవీకరించు(కూపన్_కోడ్) {
    ఒకవేళ (కూపన్_కోడ్ == "VIP_DISCOUNT_50") {
        తిరిగి_ఇవ్వు 50
    } కాకపోతే {
        తిరిగి_ఇవ్వు 0
    }
}

ఫంక్షన్ వస్తువు_ఉపమొత్తం_లెక్కించు(యూనిట్_ధర, పరిమాణం) {
    ఒకవేళ (పరిమాణం <= 0) {
        తిరిగి_ఇవ్వు 0
    }
    తిరిగి_ఇవ్వు యూనిట్_ధర * పరిమాణం
}

ఫంక్షన్ ఆర్డర్_ప్రాసెస్_చేయి(మూల_ధర, పరిమాణం, కూపన్) {
    అనుకో ఉపమొత్తం = వస్తువు_ఉపమొత్తం_లెక్కించు(మూల_ధర, పరిమాణం)
    ఒకవేళ (ఉపమొత్తం == 0) {
        తిరిగి_ఇవ్వు 0
    }
    అనుకో తగ్గింపు_శాతం = కూపన్_ధృవీకరించు(కూపన్)
    అనుకో తగ్గింపు_మొత్తం = (ఉపమొత్తం * తగ్గింపు_శాతం) / 100
    అనుకో తగ్గింపు_తర్వాత = ఉపమొత్తం - తగ్గింపు_మొత్తం
    అనుకో మొత్తం_పన్ను = (తగ్గింపు_తర్వాత * పన్ను_రేటు) / 100
    అనుకో తుది_ఇన్వాయిస్_మొత్తం = తగ్గింపు_తర్వాత + మొత్తం_పన్ను
    తిరిగి_ఇవ్వు తుది_ఇన్వాయిస్_మొత్తం
}

అనుకో తుది_ఆర్డర్ = ఆర్డర్_ప్రాసెస్_చేయి(100, 2, "VIP_DISCOUNT_50")
ముద్రించు(తుది_ఆర్డర్)
""",
        blocked_stages_expected=["ast_construction", "semantic_analysis", "symbol_table", "ir_generation", "code_generation", "code_validation", "sandbox_execution"]
    ),

    # =========================================================================
    # BENGALI DEMOS (4)
    # =========================================================================
    SecurityLabDemo(
        id="SEC-DEMO-BN-01",
        title="অ্যাকাউন্ট ও অনুমতি ব্যবস্থাপনা (Account & Permission Management)",
        language="Bengali",
        scenario_type="Demo A",
        difficulty="Intermediate",
        relative_path="examples/security_lab/bengali/sec_auth_account_bn.vital",
        description="ব্যাংকিং এবং অনুমোদন পরিষেবা যা সেশন উপস্থিতি নিশ্চিত করে কিন্তু অবজেক্ট-স্তরের মালিকানা পরীক্ষা (IDOR) বাদ দেয়।",
        defect_categories=["security", "logic", "semantic"],
        expected_findings=[
            ExpectedFinding("SEC-AUTH-001", "ভাঙ্গা অবজেক্ট-স্তরের অনুমোদন (IDOR)", "Critical", "security", 36, "কলার আইডি উৎস অ্যাকাউন্টের মালিক কিনা তা যাচাই করা হয়নি।"),
            ExpectedFinding("SEC-AUTH-003", "ছোট পরিমাণের জন্য স্থগিতাদেশ পরীক্ষা বাইপাস", "High", "logic", 41, "৫০০-এর কম পরিমাণের জন্য স্থগিত অ্যাকাউন্ট থেকে অর্থ স্থানান্তরের অনুমতি।"),
            ExpectedFinding("SEC-SEM-001", "অনির্ধারিত চলক 'অ্যাকাউন্ট_সমাপ্তি_অবস্থা'", "Medium", "semantic", 65, "চলক 'অ্যাকাউন্ট_সমাপ্তি_অবস্থা' ঘোষণার পূর্বে ব্যবহৃত।")
        ],
        expected_post_fix_behavior="স্থানান্তরের জন্য কলার_আইডি এবং উৎস_অ্যাকাউন্ট সমান হওয়া আবশ্যক এবং স্থিতি পরীক্ষা সমস্ত পরিমাণের জন্য প্রযোজ্য।",
        safe_test_inputs={"caller_id": 1042, "from_account": 1042, "to_account": 5001, "amount": 250},
        reference_fix_description="মালিকানা যাচাইকরণ যোগ করুন এবং অনির্ধারিত চলকের নাম সংশোধন করুন।",
        reference_fix_code="""মন্তব্য নিরাপদ অ্যাকাউন্ট ব্যবস্থাপনা
ধরো বর্তমান_সেশন_ব্যবহারকারী = 1042
ধরো বর্তমান_সেশন_টোকেন = "sess_live_token_77a9b"

ফাংশন সেশন_যাচাই_করো(টোকেন) {
    যদি (টোকেন == "sess_live_token_77a9b") {
        ফেরত 1
    } নাহলে {
        ফেরত 0
    }
}

ফাংশন অর্থ_স্থানান্তর_করো(কলার_আইডি, উৎস_অ্যাকাউন্ট, লক্ষ্য_অ্যাকাউন্ট, পরিমাণ) {
    ধরো সেশন_ঠিক = সেশন_যাচাই_করো(বর্তমান_সেশন_টোকেন)
    যদি (সেশন_ঠিক == 0) {
        ফেরত 0
    }
    যদি (কলার_আইডি != উৎস_অ্যাকাউন্ট) {
        ফেরত 0
    }
    ফেরত 1
}

ধরো ফলাফল = অর্থ_স্থানান্তর_করো(বর্তমান_সেশন_ব্যবহারকারী, বর্তমান_সেশন_ব্যবহারকারী, 5001, 250)
ছাপাও(ফলাফল)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-BN-02",
        title="অনিরাপদ ডেটা ও কনফিগারেশন প্রসেসিং (Unsafe Data & Config Processing)",
        language="Bengali",
        scenario_type="Demo B",
        difficulty="Intermediate",
        relative_path="examples/security_lab/bengali/sec_data_config_bn.vital",
        description="সোর্স কোডে হার্ডকোড করা গোপন চাবি, অনুপস্থিত ঊর্ধ্ব সীমানা পরীক্ষা এবং ডিবাগ লগে সংবেদনশীল তথ্য প্রকাশ।",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-DATA-001", "সোর্স কোডে হার্ডকোড করা মাস্টার গোপন চাবি", "High", "security", 8, "এমবেড করা গোপন চাবি 'sk_live_sec_prod...'."),
            ExpectedFinding("SEC-DATA-002", "ডিবাগ লগের মাধ্যমে সংবেদনশীল তথ্য প্রকাশ", "Medium", "security", 34, "অভ্যন্তরীণ ডিবাগ লগ কনসোলে গোপন চাবি প্রিন্ট করে।"),
            ExpectedFinding("SEC-DATA-003", "অফ-বাই-ওয়ান সীমানা ত্রুটি", "Low", "logic", 21, "সীমানা পরীক্ষা ৫-উপাদানের বাফারের জন্য অবৈধ সূচক ৫ অনুমোদন করে।")
        ],
        expected_post_fix_behavior="গোপন চাবি সুরক্ষিত করা হয়, সূচক < ৫ এর মধ্যে সীমাবদ্ধ থাকে।",
        safe_test_inputs={"record_index": 2, "role": "operator"},
        reference_fix_description="হার্ডকোড করা গোপন চাবি সরান এবং সূচকের সীমা ০ থেকে ৪ পর্যন্ত সীমিত করুন।",
        reference_fix_code="""মন্তব্য নিরাপদ কনফিগারেশন প্রসেসর
ধরো ডিবাগ_মোড_চালু = 0

ফাংশন কনফিগারেশন_রেকর্ড_পড়ো(রেকর্ড_সূচক, ব্যবহারকারী_ভূমিকা) {
    যদি (রেকর্ড_সূচক < 0) {
        ফেরত 0
    }
    যদি (রেকর্ড_সূচক >= 5) {
        ফেরত 0
    }
    ধরো রেকর্ড_মান = 100 + (রেকর্ড_সূচক * 25)
    ফেরত রেকর্ড_মান
}

ধরো কনফিগ_মান = কনফিগারেশন_রেকর্ড_পড়ো(2, "অপারেটর")
ছাপাও(কনফিগ_মান)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-BN-03",
        title="ইনজেকশন ও অনিরাপদ সম্পাদন প্যাটার্ন (Injection & Unsafe Execution)",
        language="Bengali",
        scenario_type="Demo C",
        difficulty="Advanced",
        relative_path="examples/security_lab/bengali/sec_injection_eval_bn.vital",
        description="ব্যবহারকারী ইনপুট থেকে ডায়নামিক SQL কোয়েরি এবং শেল কমান্ড সিঙ্ক পর্যন্ত অনিরাপদ তথ্য প্রবাহ।",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-INJ-001", "স্ট্রিং সংযোগের মাধ্যমে SQL ইনজেকশন", "High", "security", 20, "ব্যবহারকারী ইনপুট সরাসরি কোয়েরিতে যুক্ত হয়।"),
            ExpectedFinding("SEC-LEX-004", "শেল কমান্ড চেইনিং সিকোয়েন্স (';')", "Critical", "security", 31, "শেল কমান্ড স্ট্রিংয়ে সেমিকোলন রয়েছে।"),
            ExpectedFinding("SEC-IR-001", "গতিশীল কোড মূল্যায়ন সিঙ্ক (eval)", "Critical", "security", 37, "ডায়নামিক eval() কল নির্বিচারে কোড চালায়।")
        ],
        expected_post_fix_behavior="কোয়েরি প্যারামিটারের মাধ্যমে নিরাপদ করা হয়, শেল কমান্ড অপসারণ এবং eval() বাতিল করা হয়।",
        safe_test_inputs={"filter": "status=1", "cmd": "check"},
        reference_fix_description="ডেটাবেস লুকআপ প্যারামিটারের মাধ্যমে করুন এবং বিপজ্জনক eval() কল সরিয়ে ফেলুন।",
        reference_fix_code="""মন্তব্য নিরাপদ সম্পাদন জোতা
ফাংশন নিরাপদ_কোয়েরি_চালাও(অ্যাকাউন্ট_আইডি) {
    ছাপাও("প্যারামিটারাইজড নিরাপদ কোয়েরি:")
    ছাপাও(অ্যাকাউন্ট_আইডি)
    ফেরত 1
}

ধরো অবস্থা = নিরাপদ_কোয়েরি_চালাও(1042)
ছাপাও(অবস্থা)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-BN-04",
        title="জটিল ব্যবসায়িক কার্যপ্রবাহ (Complex Business Workflow)",
        language="Bengali",
        scenario_type="Demo D",
        difficulty="Advanced",
        relative_path="examples/security_lab/bengali/sec_business_workflow_bn.vital",
        description="বন্ধনী ভারসাম্যহীনতা সিনট্যাক্স ত্রুটি এবং ঋণাত্মক পরিমাণের ব্যবসায়িক যুক্তি ত্রুটিযুক্ত ই-কমার্স ইঞ্জিন।",
        defect_categories=["syntax", "logic", "security"],
        expected_findings=[
            ExpectedFinding("SEC-PAR-001", "ভারসাম্যহীন ব্লক স্কোপ ডিলিমিটার ('{' বনাম '}')", "Medium", "syntax", 42, "ঋণাত্মক চালান ব্লকের সমাপ্তি বন্ধনী '}' অনুপস্থিত।"),
            ExpectedFinding("SEC-LOGIC-001", "ঋণাত্মক পরিমাণ যাচাইয়ের অভাব (রিফান্ড শোষণ)", "High", "logic", 19, "ঋণাত্মক পরিমাণ ঋণাত্মক চালান তৈরি করে।")
        ],
        expected_post_fix_behavior="সিনট্যাক্স ব্লক বন্ধ করে, ঋণাত্মক পরিমাণ প্রত্যাখ্যান করে এবং সঠিক চালান মোট গণনা করে।",
        safe_test_inputs={"price": 100, "quantity": 2, "coupon": "VIP_DISCOUNT_50"},
        reference_fix_description="ব্লক বন্ধ করতে '}' যোগ করুন এবং পরিমাণ <= 0 যাচাই করুন।",
        reference_fix_code="""মন্তব্য নিরাপদ ই-কমার্স কার্যপ্রবাহ
ধরো কর_হার = 18

ফাংশন কুপন_যাচাই_করো(কুপন_কোড) {
    যদি (কুপন_কোড == "VIP_DISCOUNT_50") {
        ফেরত 50
    } নাহলে {
        ফেরত 0
    }
}

ফাংশন পণ্যের_উপযোগ_গণনা(একক_मूल্য, পরিমাণ) {
    যদি (পরিমাণ <= 0) {
        ফেরত 0
    }
    ফেরত একক_মূল্য * পরিমাণ
}

ফাংশন অর্ডার_প্রক্রিয়া_করো(মূল_মূল্য, পরিমাণ, কুপন) {
    ধরো উপ_যোগফল = পণ্যের_উপযোগ_গণনা(মূল_মূল্য, পরিমাণ)
    যদি (উপ_যোগফল == 0) {
        ফেরত 0
    }
    ধরো ছাড়_শতাংশ = কুপন_যাচাই_করো(কুপন)
    ধরো ছাড়_পরিমাণ = (উপ_যোগফল * ছাড়_শতাংশ) / 100
    ধরো ছাড়ের_পরে = উপ_যোগফল - ছাড়_পরিমাণ
    ধরো মোট_কর = (ছাড়ের_পরে * কর_হার) / 100
    ধরো চূড়ান্ত_চালান_পরিমাণ = ছাড়ের_পরে + মোট_কর
    ফেরত চূড়ান্ত_চালান_পরিমাণ
}

ধরো চূড়ান্ত_অর্ডার = অর্ডার_প্রক্রিয়া_করো(100, 2, "VIP_DISCOUNT_50")
ছাপাও(চূড়ান্ত_অর্ডার)
""",
        blocked_stages_expected=["ast_construction", "semantic_analysis", "symbol_table", "ir_generation", "code_generation", "code_validation", "sandbox_execution"]
    ),

    # =========================================================================
    # MARATHI DEMOS (4)
    # =========================================================================
    SecurityLabDemo(
        id="SEC-DEMO-MR-01",
        title="खाते आणि परवानगी व्यवस्थापन (Account & Permission Management)",
        language="Marathi",
        scenario_type="Demo A",
        difficulty="Intermediate",
        relative_path="examples/security_lab/marathi/sec_auth_account_mr.vital",
        description="सत्र उपस्थिती तपासणी करणारी बँकिंग आणि अधिकृतता सेवा परंतु ऑब्जेक्ट-स्तरीय मालकी तपासणी (IDOR) गहाळ आहे.",
        defect_categories=["security", "logic", "semantic"],
        expected_findings=[
            ExpectedFinding("SEC-AUTH-001", "खंडित ऑब्जेक्ट-स्तरीय अधिकृतता (IDOR)", "Critical", "security", 36, "कॉलर आयडी हा मूळ खात्याचा मालक आहे की नाही हे तपासले जात नाही."),
            ExpectedFinding("SEC-AUTH-003", "लहान रकमेसाठी खाते निलंबन तपासणी बायपास", "High", "logic", 41, "५०० पेक्षा कमी रकमेसाठी निलंबित खात्यातून वर्ग करण्यास परवानगी देते."),
            ExpectedFinding("SEC-SEM-001", "अनिर्धारित व्हेरिएबल 'खाते_शेवटची_स्थिती'", "Medium", "semantic", 65, "व्हेरिएबल 'खाते_शेवटची_स्थिती' घोषणेपूर्वी वापरले गेले आहे.")
        ],
        expected_post_fix_behavior="हस्तांतरणासाठी कॉलर_आयडी आणि मूळ_खाते समान असणे आवश्यक आहे आणि निलंबन तपासणी सर्व रकमेसाठी लागू होते.",
        safe_test_inputs={"caller_id": 1042, "from_account": 1042, "to_account": 5001, "amount": 250},
        reference_fix_description="मालकी पडताळणी जोडा आणि व्हेरिएबल नाव दुरुस्त करा.",
        reference_fix_code="""टीप सुरक्षित खाते व्यवस्थापन
घ्या चालू_सत्र_वापरकर्ता = 1042
घ्या चालू_सत्र_टोकन = "sess_live_token_77a9b"

कार्य_करा सत्र_तपासा(टोकन) {
    जर (टोकन == "sess_live_token_77a9b") {
        परत_करा 1
    } नाहीतर {
        परत_करा 0
    }
}

कार्य_करा रक्कम_वर्ग_करा(कॉलर_आयडी, मूळ_खाते, लक्ष्य_खाते, रक्कम) {
    घ्या सत्र_योग्य = सत्र_तपासा(चालू_सत्र_टोकन)
    जर (सत्र_योग्य == 0) {
        परत_करा 0
    }
    जर (कॉलर_आयडी != मूळ_खाते) {
        परत_करा 0
    }
    परत_करा 1
}

घ्या निकाल = रक्कम_वर्ग_करा(चालू_सत्र_वापरकर्ता, चालू_सत्र_वापरकर्ता, 5001, 250)
लिहा(निकाल)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-MR-02",
        title="असुरक्षित डेटा आणि कॉन्फिगरेशन (Unsafe Data & Config Processing)",
        language="Marathi",
        scenario_type="Demo B",
        difficulty="Intermediate",
        relative_path="examples/security_lab/marathi/sec_data_config_mr.vital",
        description="सोर्स कोडमध्ये हार्डकोड केलेली गुप्त की, वरच्या मर्यादेची तपासणी नसणे आणि डीबग लॉगमध्ये क्रेडेंशियल उघड करणे.",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-DATA-001", "सोर्स कोडमध्ये मास्टर गुप्त की हार्डकोड केली आहे", "High", "security", 8, "एम्बेडेड उत्पादन की 'sk_live_sec_prod...'."),
            ExpectedFinding("SEC-DATA-002", "डीबग लॉगद्वारे संवेदनशील माहिती उघड करणे", "Medium", "security", 34, "अंतर्गत डीबग लॉगर कन्सोलमध्ये गुप्त की मुद्रित करतो."),
            ExpectedFinding("SEC-DATA-003", "ऑफ-बाय-वन मर्यादा त्रुटी", "Low", "logic", 21, "५-घटक बफरसाठी अवैध निर्देशांक ५ ची परवानगी देते.")
        ],
        expected_post_fix_behavior="गुप्त की सुरक्षित ठेवली जाते, निर्देशांक मर्यादा < ५ पर्यंत मर्यादित असते.",
        safe_test_inputs={"record_index": 2, "role": "operator"},
        reference_fix_description="हार्डकोड केलेली गुप्त की काढून टाका आणि निर्देशांक मर्यादा ० ते ४ पर्यंत मर्यादित करा.",
        reference_fix_code="""टीप सुरक्षित कॉन्फिगरेशन प्रोसेसर
घ्या डीबग_मोड_सक्रिय = 0

कार्य_करा कॉन्फिगरेशन_नोंद_वाचा(नोंद_क्रमांक, वापरकर्ता_भूमिका) {
    जर (नोंद_क्रमांक < 0) {
        परत_करा 0
    }
    जर (नोंद_क्रमांक >= 5) {
        परत_करा 0
    }
    घ्या नोंद_मूल्य = 100 + (नोंद_क्रमांक * 25)
    परत_करा नोंद_मूल्य
}

घ्या कॉन्फिग_मूल्य = कॉन्फिगरेशन_नोंद_वाचा(2, "ऑपरेटर")
लिहा(कॉन्फिग_मूल्य)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-MR-03",
        title="इंजेक्शन आणि असुरक्षित अंमलबजावणी (Injection & Unsafe Execution)",
        language="Marathi",
        scenario_type="Demo C",
        difficulty="Advanced",
        relative_path="examples/security_lab/marathi/sec_injection_eval_mr.vital",
        description="वापरकर्ता इनपुटवरून डायनॅमिक SQL आणि शेल कमांड सिंकपर्यंत असुरक्षित प्रवाह.",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-INJ-001", "स्ट्रिंग जोडणीद्वारे SQL इंजेक्शन", "High", "security", 20, "वापरकर्ता इनपुट थेट क्वेरीमध्ये जोडले जाते."),
            ExpectedFinding("SEC-LEX-004", "शेल कमांड चेनिंग सीक्वेन्स (';')", "Critical", "security", 31, "शेल कमांड स्ट्रिंगमध्ये अनकोटेड अर्धविराम आहे."),
            ExpectedFinding("SEC-IR-001", "डायनॅमिक कोड मूल्यमापन सिंक (eval)", "Critical", "security", 37, "डायनॅमिक eval() कॉल अनियंत्रित कोड चालवतो.")
        ],
        expected_post_fix_behavior="क्वेरी पॅरामीटराइज केल्या जातात, शेल कमांड काढून टाकल्या जातात आणि eval() पूर्णपणे वगळले जाते.",
        safe_test_inputs={"filter": "status=1", "cmd": "check"},
        reference_fix_description="डेटाबेस लुकअप पॅरामीटराइज करा आणि धोकादायक eval() कॉल काढून टाका.",
        reference_fix_code="""टीप सुरक्षित अंमलबजावणी चाचणी
कार्य_करा सुरक्षित_क्वेरी_चालवा(खाते_आयडी) {
    लिहा("पॅरामीटराइज्ड सुरक्षित क्वेरी:")
    लिहा(खाते_आयडी)
    परत_करा 1
}

घ्या स्थिती = सुरक्षित_क्वेरी_चालवा(1042)
लिहा(स्थिती)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-MR-04",
        title="जटिल व्यवसाय वर्कफ्लो (Complex Business Workflow)",
        language="Marathi",
        scenario_type="Demo D",
        difficulty="Advanced",
        relative_path="examples/security_lab/marathi/sec_business_workflow_mr.vital",
        description="कंस असंतुलन सिंटॅक्स त्रुटी आणि ऋण प्रमाणाची व्यवसाय तर्क त्रुटी असलेले ई-कॉमर्स ऑर्डर इंजिन.",
        defect_categories=["syntax", "logic", "security"],
        expected_findings=[
            ExpectedFinding("SEC-PAR-001", "असंतुलित ब्लॉक स्कोप डिलिमिटर्स ('{' विरुद्ध '}')", "Medium", "syntax", 42, "ऋण देयक ब्लॉकवर अंतिम कंस '}' गहाळ आहे."),
            ExpectedFinding("SEC-LOGIC-001", "ऋण प्रमाण तपासणीचा अभाव (रिफंड गैरवापर)", "High", "logic", 19, "ऋण प्रमाणामुळे देयक रक्कम ऋण बनते.")
        ],
        expected_post_fix_behavior="सिंटॅक्स ब्लॉक बंद करतो, ऋण प्रमाण नाकारतो आणि योग्य अंतिम रक्कम मोजतो.",
        safe_test_inputs={"price": 100, "quantity": 2, "coupon": "VIP_DISCOUNT_50"},
        reference_fix_description="ब्लॉक बंद करण्यासाठी '}' जोडा आणि प्रमाण <= 0 तपासा.",
        reference_fix_code="""टीप सुरक्षित ई-कॉमर्स वर्कफ्लो
घ्या कर_दर = 18

कार्य_करा कूपन_तपासा(कूपन_कोड) {
    जर (कूपन_कोड == "VIP_DISCOUNT_50") {
        परत_करा 50
    } नाहीतर {
        परत_करा 0
    }
}

कार्य_करा वस्तू_उपयोग_गणना(एकक_किंमत, प्रमाण) {
    जर (प्रमाण <= 0) {
        परत_करा 0
    }
    परत_करा एकक_किंमत * प्रमाण
}

कार्य_करा ऑर्डर_प्रक्रिया_करा(मूळ_किंमत, प्रमाण, कूपन) {
    घ्या उप_बेरीज = वस्तू_उपयोग_गणना(मूळ_किंमत, प्रमाण)
    जर (उप_बेरीज == 0) {
        परत_करा 0
    }
    घ्या सूट_टक्के = कूपन_तपासा(कूपन)
    घ्या सूट_रक्कम = (उप_बेरीज * सूट_टक्के) / 100
    घ्या सूटनंतर_रक्कम = उप_बेरीज - सूट_रक्कम
    घ्या एकूण_कर = (सूटनंतर_रक्कम * कर_दर) / 100
    घ्या अंतिम_देयक_रक्कम = सूटनंतर_रक्कम + एकूण_कर
    परत_करा अंतिम_देयक_रक्कम
}

घ्या अंतिम_ऑर्डर = ऑर्डर_प्रक्रिया_करा(100, 2, "VIP_DISCOUNT_50")
लिहा(अंतिम_ऑर्डर)
""",
        blocked_stages_expected=["ast_construction", "semantic_analysis", "symbol_table", "ir_generation", "code_generation", "code_validation", "sandbox_execution"]
    ),

    # =========================================================================
    # NEPALI DEMOS (4)
    # =========================================================================
    SecurityLabDemo(
        id="SEC-DEMO-NE-01",
        title="खाता र अनुमति व्यवस्थापन (Account & Permission Management)",
        language="Nepali",
        scenario_type="Demo A",
        difficulty="Intermediate",
        relative_path="examples/security_lab/nepali/sec_auth_account_ne.vital",
        description="सत्र उपस्थिति प्रमाणीकरण गर्ने बैंकिङ सेवा तर वस्तु-स्तर स्वामित्व जाँच (IDOR) को अभाव।",
        defect_categories=["security", "logic", "semantic"],
        expected_findings=[
            ExpectedFinding("SEC-AUTH-001", "टुटेको वस्तु-स्तर प्रमाणीकरण (IDOR)", "Critical", "security", 36, "कलर आईडी स्रोत खाताको मालिक हो कि होइन प्रमाणीकरण गरिएको छैन।"),
            ExpectedFinding("SEC-AUTH-003", "सानो रकमको लागि निलम्बन जाँच बाइपास", "High", "logic", 41, "५०० भन्दा कम रकमको लागि निलम्बित खाताबाट रकम स्थानान्तरण अनुमति।"),
            ExpectedFinding("SEC-SEM-001", "अनिर्धारित चल 'खाता_अन्तिम_स्थिति'", "Medium", "semantic", 65, "चल 'खाता_अन्तिम_स्थिति' घोषणा अघि प्रयोग गरिएको।")
        ],
        expected_post_fix_behavior="रकम पठाउन कलर_आईडी र स्रोत_खाता समान हुनुपर्छ र निलम्बन जाँच सबै रकममा लागू हुन्छ।",
        safe_test_inputs={"caller_id": 1042, "from_account": 1042, "to_account": 5001, "amount": 250},
        reference_fix_description="स्वामित्व प्रमाणीकरण थप्नुहोस् र चलको नाम सच्याउनुहोस्।",
        reference_fix_code="""टिप्पणी_गर सुरक्षित खाता व्यवस्थापन
मान वर्तमान_सत्र_प्रयोगकर्ता = 1042
मान वर्तमान_सत्र_टोकन = "sess_live_token_77a9b"

कार्य_गर सत्र_जाँच_गर(टोकन) {
    यदि_हो (टोकन == "sess_live_token_77a9b") {
        फिर्ता 1
    } नत्र {
        फिर्ता 0
    }
}

कार्य_गर रकम_पठाउ(कलर_आईडी, स्रोत_खाता, लक्ष्य_खाता, रकम) {
    मान सत्र_ठीक = सत्र_जाँच_गर(वर्तमान_सत्र_टोकन)
    यदि_हो (सत्र_ठीक == 0) {
        फिर्ता 0
    }
    यदि_हो (कलर_आईडी != स्रोत_खाता) {
        फिर्ता 0
    }
    फिर्ता 1
}

मान परिणाम = रकम_पठाउ(वर्तमान_सत्र_प्रयोगकर्ता, वर्तमान_सत्र_प्रयोगकर्ता, 5001, 250)
छाप(परिणाम)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-NE-02",
        title="असुरक्षित डेटा र कन्फिगरेसन (Unsafe Data & Config Processing)",
        language="Nepali",
        scenario_type="Demo B",
        difficulty="Intermediate",
        relative_path="examples/security_lab/nepali/sec_data_config_ne.vital",
        description="स्रोत कोडमा हार्डकोड गरिएको मास्टर गोप्य कुञ्जी, माथिल्लो सीमा जाँच नहुनु र डिबग लगमा डेटा प्रकटीकरण।",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-DATA-001", "स्रोत कोडमा मास्टर गोप्य कुञ्जी हार्डकोड गरिएको", "High", "security", 8, "एम्बेडेड उत्पादन कुञ्जी 'sk_live_sec_prod...'."),
            ExpectedFinding("SEC-DATA-002", "डिबग लग मार्फत संवेदनशील जानकारी प्रकटीकरण", "Medium", "security", 34, "आन्तरिक डिबग लगरले कन्सोलमा गोप्य कुञ्जी छाप्छ।"),
            ExpectedFinding("SEC-DATA-003", "अफ-बाई-वन सीमा त्रुटि", "Low", "logic", 21, "५-तत्व बफरको लागि अमान्य सूचकांक ५ अनुमति दिन्छ।")
        ],
        expected_post_fix_behavior="गोप्य कुञ्जी सुरक्षित गरिन्छ, सूचकांक सीमा < ५ सम्म सीमित रहन्छ।",
        safe_test_inputs={"record_index": 2, "role": "operator"},
        reference_fix_description="हार्डकोड गरिएको कुञ्जी हटाउनुहोस् र सूचकांक सीमा ० देखि ४ सम्म सीमित गर्नुहोस्।",
        reference_fix_code="""टिप्पणी_गर सुरक्षित कन्फिगरेसन प्रोसेसर
मान डिबग_मोड_सक्रिय = 0

कार्य_गर कन्फिगरेसन_रेकर्ड_पढ(रेकर्ड_सूचकांक, प्रयोगकर्ता_भूमिका) {
    यदि_हो (रेकर्ड_सूचकांक < 0) {
        फिर्ता 0
    }
    यदि_हो (रेकर्ड_सूचकांक >= 5) {
        फिर्ता 0
    }
    मान रेकर्ड_मान = 100 + (रेकर्ड_सूचकांक * 25)
    फिर्ता रेकर्ड_मान
}

मान कन्फिग_मान = कन्फिगरेसन_रेकर्ड_पढ(2, "अपरेटर")
छाप(कन्फिग_मान)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-NE-03",
        title="इन्जेक्सन र असुरक्षित कार्यान्वयन (Injection & Unsafe Execution)",
        language="Nepali",
        scenario_type="Demo C",
        difficulty="Advanced",
        relative_path="examples/security_lab/nepali/sec_injection_eval_ne.vital",
        description="प्रयोगकर्ता इनपुटबाट गतिशील SQL र शेल कमाण्ड सिङ्कसम्म अनियन्त्रित डेटा प्रवाह।",
        defect_categories=["security", "logic"],
        expected_findings=[
            ExpectedFinding("SEC-INJ-001", "स्ट्रिङ संयोजन मार्फत SQL इन्जेक्सन", "High", "security", 20, "प्रयोगकर्ता इनपुट सिधै क्वेरीमा जोडिन्छ।"),
            ExpectedFinding("SEC-LEX-004", "शेल कमाण्ड चेनिङ अनुक्रम (';')", "Critical", "security", 31, "शेल कमाण्ड स्ट्रिङमा अनकोटेड अर्धविराम समावेश छ।"),
            ExpectedFinding("SEC-IR-001", "गतिशील कोड मूल्याङ्कन सिङ्क (eval)", "Critical", "security", 37, "गतिशील eval() कलले अनियन्त्रित कोड कार्यान्वयन गर्छ।")
        ],
        expected_post_fix_behavior="क्वेरीहरू प्यारामिटराइज गरिन्छ, शेल कमाण्ड हटाइन्छ र eval() पूर्ण रूपमा रद्द गरिन्छ।",
        safe_test_inputs={"filter": "status=1", "cmd": "check"},
        reference_fix_description="डेटाबेस लुकअप प्यारामिटराइज गर्नुहोस् र खतरनाक eval() कलहरू हटाउनुहोस्।",
        reference_fix_code="""टिप्पणी_गर सुरक्षित कार्यान्वयन परीक्षण
कार्य_गर सुरक्षित_क्वेरी_चलाउ(खाता_आईडी) {
    छाप("प्यारामिटराइज्ड सुरक्षित क्वेरी:")
    छाप(खाता_आईडी)
    फिर्ता 1
}

मान स्थिति = सुरक्षित_क्वेरी_चलाउ(1042)
छाप(स्थिति)
"""
    ),

    SecurityLabDemo(
        id="SEC-DEMO-NE-04",
        title="जटिल व्यापार कार्यप्रवाह (Complex Business Workflow)",
        language="Nepali",
        scenario_type="Demo D",
        difficulty="Advanced",
        relative_path="examples/security_lab/nepali/sec_business_workflow_ne.vital",
        description="कोष्ठक असन्तुलन सिन्ट्याक्स त्रुटि र ऋणात्मक मात्राको व्यापार तर्क त्रुटि भएको ई-कमर्स अर्डर इन्जिन।",
        defect_categories=["syntax", "logic", "security"],
        expected_findings=[
            ExpectedFinding("SEC-PAR-001", "असन्तुलित ब्लक स्कोप डिलिमिटर ('{' विरुद्ध '}')", "Medium", "syntax", 42, "ऋणात्मक बीजक ब्लकमा समापन कोष्ठक '}' छुटेको छ।"),
            ExpectedFinding("SEC-LOGIC-001", "ऋणात्मक मात्रा प्रमाणीकरणको अभाव (फिर्ता दुरुपयोग)", "High", "logic", 19, "ऋणात्मक मात्राले बीजक रकम ऋणात्मक बनाउँछ।")
        ],
        expected_post_fix_behavior="सिन्ट्याक्स ब्लक बन्द गर्छ, ऋणात्मक मात्रा अस्वीकार गर्छ र सही अन्तिम बीजक गणना गर्छ।",
        safe_test_inputs={"price": 100, "quantity": 2, "coupon": "VIP_DISCOUNT_50"},
        reference_fix_description="ब्लक बन्द गर्न '}' थप्नुहोस् र मात्रा <= 0 जाँच गर्नुहोस्।",
        reference_fix_code="""टिप्पणी_गर सुरक्षित ई-कमर्स कार्यप्रवाह
मान कर_दर = 18

कार्य_गर कुपन_जाँच_गर(कुपन_कोड) {
    यदि_हो (कुपन_कोड == "VIP_DISCOUNT_50") {
        फिर्ता 50
    } नत्र {
        फिर्ता 0
    }
}

कार्य_गर वस्तु_उपयोग_गणना(इकाई_मूल्य, मात्रा) {
    यदि_हो (मात्रा <= 0) {
        फिर्ता 0
    }
    फिर्ता इकाई_मूल्य * मात्रा
}

कार्य_गर अर्डर_प्रक्रिया_गर(मूल_मूल्य, मात्रा, कुपन) {
    मान उप_योग = वस्तु_उपयोग_गणना(मूल_मूल्य, मात्रा)
    यदि_हो (उप_योग == 0) {
        फिर्ता 0
    }
    मान छुट_प्रतिशत = कुपन_जाँच_गर(कुपन)
    मान छुट_रकम = (उप_योग * छुट_प्रतिशत) / 100
    मान छुटनपछिको_रकम = उप_योग - छुट_रकम
    मान जम्मा_कर = (छुटनपछिको_रकम * कर_दर) / 100
    मान अन्तिम_बीजक_रकम = छुटनपछिको_रकम + जम्मा_कर
    फिर्ता अन्तिम_बीजक_रकम
}

मान अन्तिम_अर्डर = अर्डर_प्रक्रिया_गर(100, 2, "VIP_DISCOUNT_50")
छाप(अन्तिम_अर्डर)
""",
        blocked_stages_expected=["ast_construction", "semantic_analysis", "symbol_table", "ir_generation", "code_generation", "code_validation", "sandbox_execution"]
    )
]

# Map lookup by ID and by relative path
_DEMO_BY_ID: Dict[str, SecurityLabDemo] = {d.id: d for d in SECURITY_LAB_DEMOS}
_DEMO_BY_PATH: Dict[str, SecurityLabDemo] = {d.relative_path.replace('\\', '/').lower(): d for d in SECURITY_LAB_DEMOS}


def get_all_security_lab_demos() -> List[Dict[str, Any]]:
    """Returns list of all registered Security Lab demos as dictionaries."""
    return [d.to_dict() for d in SECURITY_LAB_DEMOS]


def get_security_lab_demo_by_id(demo_id: str) -> Optional[SecurityLabDemo]:
    """Retrieves a Security Lab demo by its unique ID."""
    return _DEMO_BY_ID.get(demo_id)


def get_security_lab_demo_by_path(rel_path: str) -> Optional[SecurityLabDemo]:
    """Retrieves a Security Lab demo by its relative file path."""
    norm = rel_path.replace('\\', '/').lower().lstrip('/')
    for path_key, demo in _DEMO_BY_PATH.items():
        if norm.endswith(path_key) or path_key.endswith(norm):
            return demo
    return None


def get_demos_by_language(language: str) -> List[SecurityLabDemo]:
    """Returns demos for a specific language."""
    target = language.lower()
    return [d for d in SECURITY_LAB_DEMOS if d.language.lower() == target]
