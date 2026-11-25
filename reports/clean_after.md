# VITAL Cross-UI Number Consistency Audit Report

**Total Demos Audited:** 79  
**Clean Consistent Demos:** 51  
**Demos with Disagreements (Mismatches):** 28  

## 1. Summary of Identified Disagreements

| # | File Path | Language | Category | Overall Status | Mismatch Description |
|---|-----------|----------|----------|----------------|----------------------|
| 1 | `examples/security_lab/bengali/sec_auth_account_bn.vital` | Bengali | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1); syntax_analysis: Badge (0) != Dialog Metric (1); ast_construction: Badge (0) != Dialog Metric (1) |
| 2 | `examples/security_lab/bengali/sec_business_workflow_bn.vital` | Bengali | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1) |
| 3 | `examples/security_lab/bengali/sec_data_config_bn.vital` | Bengali | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (5); lexical_analysis: Badge (0) != Dialog Metric (5); syntax_analysis: Badge (0) != Dialog Metric (5); ast_construction: Badge (0) != Dialog Metric (5); semantic_analysis: Badge (0) != Dialog Metric (5); symbol_table: Badge (0) != Dialog Metric (5); ir_generation: Badge (0) != Dialog Metric (5); optimization: Badge (0) != Dialog Metric (5); code_generation: Badge (0) != Dialog Metric (5); code_validation: Badge (0) != Dialog Metric (5) |
| 4 | `examples/security_lab/bengali/sec_injection_eval_bn.vital` | Bengali | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (4); lexical_analysis: Badge (0) != Dialog Metric (4); syntax_analysis: Badge (0) != Dialog Metric (4); ast_construction: Badge (0) != Dialog Metric (4); semantic_analysis: Badge (0) != Dialog Metric (4); symbol_table: Badge (0) != Dialog Metric (4); ir_generation: Badge (0) != Dialog Metric (4); optimization: Badge (0) != Dialog Metric (4); code_generation: Badge (0) != Dialog Metric (4); code_validation: Badge (0) != Dialog Metric (4) |
| 5 | `examples/security_lab/english/sec_auth_account.vital` | English | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1); syntax_analysis: Badge (0) != Dialog Metric (1); ast_construction: Badge (0) != Dialog Metric (1) |
| 6 | `examples/security_lab/english/sec_business_workflow.vital` | English | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1) |
| 7 | `examples/security_lab/english/sec_data_config.vital` | English | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (5); lexical_analysis: Badge (0) != Dialog Metric (5); syntax_analysis: Badge (0) != Dialog Metric (5); ast_construction: Badge (0) != Dialog Metric (5); semantic_analysis: Badge (0) != Dialog Metric (5); symbol_table: Badge (0) != Dialog Metric (5); ir_generation: Badge (0) != Dialog Metric (5); optimization: Badge (0) != Dialog Metric (5); code_generation: Badge (0) != Dialog Metric (5); code_validation: Badge (0) != Dialog Metric (5) |
| 8 | `examples/security_lab/english/sec_injection_eval.vital` | English | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (4); lexical_analysis: Badge (0) != Dialog Metric (4); syntax_analysis: Badge (0) != Dialog Metric (4); ast_construction: Badge (0) != Dialog Metric (4); semantic_analysis: Badge (0) != Dialog Metric (4); symbol_table: Badge (0) != Dialog Metric (4); ir_generation: Badge (0) != Dialog Metric (4); optimization: Badge (0) != Dialog Metric (4); code_generation: Badge (0) != Dialog Metric (4); code_validation: Badge (0) != Dialog Metric (4) |
| 9 | `examples/security_lab/fusion/sec_auth_account_fusion.vital` | Multilingual Fusion | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1); syntax_analysis: Badge (0) != Dialog Metric (1); ast_construction: Badge (0) != Dialog Metric (1) |
| 10 | `examples/security_lab/fusion/sec_business_workflow_fusion.vital` | Multilingual Fusion | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1) |
| 11 | `examples/security_lab/fusion/sec_data_config_fusion.vital` | Multilingual Fusion | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (5); lexical_analysis: Badge (0) != Dialog Metric (5); syntax_analysis: Badge (0) != Dialog Metric (5); ast_construction: Badge (0) != Dialog Metric (5); semantic_analysis: Badge (0) != Dialog Metric (5); symbol_table: Badge (0) != Dialog Metric (5); ir_generation: Badge (0) != Dialog Metric (5); optimization: Badge (0) != Dialog Metric (5); code_generation: Badge (0) != Dialog Metric (5); code_validation: Badge (0) != Dialog Metric (5) |
| 12 | `examples/security_lab/fusion/sec_injection_eval_fusion.vital` | Multilingual Fusion | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (4); lexical_analysis: Badge (0) != Dialog Metric (4); syntax_analysis: Badge (0) != Dialog Metric (4); ast_construction: Badge (0) != Dialog Metric (4); semantic_analysis: Badge (0) != Dialog Metric (4); symbol_table: Badge (0) != Dialog Metric (4); ir_generation: Badge (0) != Dialog Metric (4); optimization: Badge (0) != Dialog Metric (4); code_generation: Badge (0) != Dialog Metric (4); code_validation: Badge (0) != Dialog Metric (4) |
| 13 | `examples/security_lab/hindi/sec_auth_account_hi.vital` | Hindi | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1); syntax_analysis: Badge (0) != Dialog Metric (1); ast_construction: Badge (0) != Dialog Metric (1) |
| 14 | `examples/security_lab/hindi/sec_business_workflow_hi.vital` | Hindi | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1) |
| 15 | `examples/security_lab/hindi/sec_data_config_hi.vital` | Hindi | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (5); lexical_analysis: Badge (0) != Dialog Metric (5); syntax_analysis: Badge (0) != Dialog Metric (5); ast_construction: Badge (0) != Dialog Metric (5); semantic_analysis: Badge (0) != Dialog Metric (5); symbol_table: Badge (0) != Dialog Metric (5); ir_generation: Badge (0) != Dialog Metric (5); optimization: Badge (0) != Dialog Metric (5); code_generation: Badge (0) != Dialog Metric (5); code_validation: Badge (0) != Dialog Metric (5) |
| 16 | `examples/security_lab/hindi/sec_injection_eval_hi.vital` | Hindi | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (4); lexical_analysis: Badge (0) != Dialog Metric (4); syntax_analysis: Badge (0) != Dialog Metric (4); ast_construction: Badge (0) != Dialog Metric (4); semantic_analysis: Badge (0) != Dialog Metric (4); symbol_table: Badge (0) != Dialog Metric (4); ir_generation: Badge (0) != Dialog Metric (4); optimization: Badge (0) != Dialog Metric (4); code_generation: Badge (0) != Dialog Metric (4); code_validation: Badge (0) != Dialog Metric (4) |
| 17 | `examples/security_lab/marathi/sec_auth_account_mr.vital` | Marathi | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1); syntax_analysis: Badge (0) != Dialog Metric (1); ast_construction: Badge (0) != Dialog Metric (1) |
| 18 | `examples/security_lab/marathi/sec_business_workflow_mr.vital` | Marathi | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1) |
| 19 | `examples/security_lab/marathi/sec_data_config_mr.vital` | Marathi | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (4); lexical_analysis: Badge (0) != Dialog Metric (4); syntax_analysis: Badge (0) != Dialog Metric (4); ast_construction: Badge (0) != Dialog Metric (4); semantic_analysis: Badge (0) != Dialog Metric (4); symbol_table: Badge (0) != Dialog Metric (4); ir_generation: Badge (0) != Dialog Metric (4); optimization: Badge (0) != Dialog Metric (4); code_generation: Badge (0) != Dialog Metric (4); code_validation: Badge (0) != Dialog Metric (4) |
| 20 | `examples/security_lab/marathi/sec_injection_eval_mr.vital` | Marathi | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (4); lexical_analysis: Badge (0) != Dialog Metric (4); syntax_analysis: Badge (0) != Dialog Metric (4); ast_construction: Badge (0) != Dialog Metric (4); semantic_analysis: Badge (0) != Dialog Metric (4); symbol_table: Badge (0) != Dialog Metric (4); ir_generation: Badge (0) != Dialog Metric (4); optimization: Badge (0) != Dialog Metric (4); code_generation: Badge (0) != Dialog Metric (4); code_validation: Badge (0) != Dialog Metric (4); Fix Dialog Total (25) != Rendered Rows (26) |
| 21 | `examples/security_lab/nepali/sec_auth_account_ne.vital` | Nepali | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1); syntax_analysis: Badge (0) != Dialog Metric (1); ast_construction: Badge (0) != Dialog Metric (1) |
| 22 | `examples/security_lab/nepali/sec_business_workflow_ne.vital` | Nepali | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1) |
| 23 | `examples/security_lab/nepali/sec_data_config_ne.vital` | Nepali | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (4); lexical_analysis: Badge (0) != Dialog Metric (4); syntax_analysis: Badge (0) != Dialog Metric (4); ast_construction: Badge (0) != Dialog Metric (4); semantic_analysis: Badge (0) != Dialog Metric (4); symbol_table: Badge (0) != Dialog Metric (4); ir_generation: Badge (0) != Dialog Metric (4); optimization: Badge (0) != Dialog Metric (4); code_generation: Badge (0) != Dialog Metric (4); code_validation: Badge (0) != Dialog Metric (4) |
| 24 | `examples/security_lab/nepali/sec_injection_eval_ne.vital` | Nepali | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (4); lexical_analysis: Badge (0) != Dialog Metric (4); syntax_analysis: Badge (0) != Dialog Metric (4); ast_construction: Badge (0) != Dialog Metric (4); semantic_analysis: Badge (0) != Dialog Metric (4); symbol_table: Badge (0) != Dialog Metric (4); ir_generation: Badge (0) != Dialog Metric (4); optimization: Badge (0) != Dialog Metric (4); code_generation: Badge (0) != Dialog Metric (4); code_validation: Badge (0) != Dialog Metric (4) |
| 25 | `examples/security_lab/telugu/sec_auth_account_te.vital` | Telugu | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1); syntax_analysis: Badge (0) != Dialog Metric (1); ast_construction: Badge (0) != Dialog Metric (1) |
| 26 | `examples/security_lab/telugu/sec_business_workflow_te.vital` | Telugu | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (1); lexical_analysis: Badge (0) != Dialog Metric (1) |
| 27 | `examples/security_lab/telugu/sec_data_config_te.vital` | Telugu | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (5); lexical_analysis: Badge (0) != Dialog Metric (5); syntax_analysis: Badge (0) != Dialog Metric (5); ast_construction: Badge (0) != Dialog Metric (5); semantic_analysis: Badge (0) != Dialog Metric (5); symbol_table: Badge (0) != Dialog Metric (5); ir_generation: Badge (0) != Dialog Metric (5); optimization: Badge (0) != Dialog Metric (5); code_generation: Badge (0) != Dialog Metric (5); code_validation: Badge (0) != Dialog Metric (5) |
| 28 | `examples/security_lab/telugu/sec_injection_eval_te.vital` | Telugu | Security Lab | BLOCKED | source_input: Badge (0) != Dialog Metric (4); lexical_analysis: Badge (0) != Dialog Metric (4); syntax_analysis: Badge (0) != Dialog Metric (4); ast_construction: Badge (0) != Dialog Metric (4); semantic_analysis: Badge (0) != Dialog Metric (4); symbol_table: Badge (0) != Dialog Metric (4); ir_generation: Badge (0) != Dialog Metric (4); optimization: Badge (0) != Dialog Metric (4); code_generation: Badge (0) != Dialog Metric (4); code_validation: Badge (0) != Dialog Metric (4); Fix Dialog Total (24) != Rendered Rows (25) |

## 2. Detailed Per-Demo Audit Table

| File Path | Status | Preflight Sec | Health Score | Dead Code % | Fix All Btn | Fix Dialog (Res/Tot) | Mismatch? |
|-----------|--------|---------------|--------------|-------------|-------------|----------------------|-----------|
| `examples/bengali/arithmetic.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/bengali/conditions.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/bengali/ecommerce_order_processor.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/bengali/hello.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/bengali/hospital_patient_registry.vital` | COMPLETED | 0 (0 high) | 98 | 0% | 0 | - | **NO** |
| `examples/bengali/loops.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/bengali/sorting_algorithms_benchmark.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/english/arithmetic.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/english/conditions.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/english/graph_shortest_path.vital` | COMPLETED | 0 (0 high) | 90 | 0% | 0 | - | **NO** |
| `examples/english/hello.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/english/inventory_management_system.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/english/loops.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/english/student_grade_report.vital` | COMPLETED | 0 (0 high) | 98 | 0% | 0 | - | **NO** |
| `examples/fusion/fusion_autonomous_robot.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/fusion/fusion_data_pipeline.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/fusion/fusion_stock_exchange.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/hindi/arithmetic.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/hindi/bank_ledger_system.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/hindi/conditions.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/hindi/hello.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/hindi/library_catalog_system.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/hindi/loops.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/hindi/matrix_operations_suite.vital` | COMPLETED | 0 (0 high) | 97 | 0% | 0 | - | **NO** |
| `examples/marathi/arithmetic.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/marathi/conditions.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/marathi/cryptography_cipher_toolkit.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/marathi/hello.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/marathi/loops.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/marathi/payroll_tax_calculator.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/marathi/smart_energy_meter.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/nepali/arithmetic.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/nepali/conditions.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/nepali/financial_investment_portfolio.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/nepali/flight_reservation_system.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/nepali/hello.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/nepali/loops.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/nepali/weather_station_analytics.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/security_lab/bengali/sec_auth_account_bn.vital` | BLOCKED | 2 (2 high) | 86 | 13.3% | 24 | 18/24 | **YES** |
| `examples/security_lab/bengali/sec_business_workflow_bn.vital` | BLOCKED | 2 (1 high) | 75 | 0% | 3 | - | **YES** |
| `examples/security_lab/bengali/sec_data_config_bn.vital` | BLOCKED | 5 (2 high) | 95 | 10% | 30 | - | **YES** |
| `examples/security_lab/bengali/sec_injection_eval_bn.vital` | BLOCKED | 4 (4 high) | 94 | 11.5% | 24 | - | **YES** |
| `examples/security_lab/english/sec_auth_account.vital` | BLOCKED | 2 (2 high) | 86 | 13.7% | 25 | 19/25 | **YES** |
| `examples/security_lab/english/sec_business_workflow.vital` | BLOCKED | 2 (1 high) | 75 | 0% | 3 | - | **YES** |
| `examples/security_lab/english/sec_data_config.vital` | BLOCKED | 5 (2 high) | 95 | 10% | 30 | - | **YES** |
| `examples/security_lab/english/sec_injection_eval.vital` | BLOCKED | 4 (4 high) | 94 | 12.1% | 25 | - | **YES** |
| `examples/security_lab/fusion/sec_auth_account_fusion.vital` | BLOCKED | 2 (2 high) | 86 | 13.7% | 25 | 18/25 | **YES** |
| `examples/security_lab/fusion/sec_business_workflow_fusion.vital` | BLOCKED | 2 (1 high) | 75 | 0% | 3 | - | **YES** |
| `examples/security_lab/fusion/sec_data_config_fusion.vital` | BLOCKED | 5 (2 high) | 95 | 10% | 30 | - | **YES** |
| `examples/security_lab/fusion/sec_injection_eval_fusion.vital` | BLOCKED | 4 (4 high) | 94 | 12.1% | 25 | - | **YES** |
| `examples/security_lab/hindi/sec_auth_account_hi.vital` | BLOCKED | 2 (2 high) | 86 | 13.3% | 24 | 18/24 | **YES** |
| `examples/security_lab/hindi/sec_business_workflow_hi.vital` | BLOCKED | 2 (1 high) | 75 | 0% | 3 | - | **YES** |
| `examples/security_lab/hindi/sec_data_config_hi.vital` | BLOCKED | 5 (2 high) | 95 | 10% | 30 | - | **YES** |
| `examples/security_lab/hindi/sec_injection_eval_hi.vital` | BLOCKED | 4 (4 high) | 94 | 12.1% | 25 | - | **YES** |
| `examples/security_lab/marathi/sec_auth_account_mr.vital` | BLOCKED | 2 (2 high) | 86 | 13.3% | 24 | 15/24 | **YES** |
| `examples/security_lab/marathi/sec_business_workflow_mr.vital` | BLOCKED | 2 (1 high) | 75 | 0% | 3 | - | **YES** |
| `examples/security_lab/marathi/sec_data_config_mr.vital` | BLOCKED | 4 (2 high) | 95 | 10% | 29 | - | **YES** |
| `examples/security_lab/marathi/sec_injection_eval_mr.vital` | BLOCKED | 4 (4 high) | 94 | 12.1% | 25 | 20/25 | **YES** |
| `examples/security_lab/nepali/sec_auth_account_ne.vital` | BLOCKED | 2 (2 high) | 86 | 13.3% | 24 | 18/24 | **YES** |
| `examples/security_lab/nepali/sec_business_workflow_ne.vital` | BLOCKED | 2 (1 high) | 75 | 0% | 3 | - | **YES** |
| `examples/security_lab/nepali/sec_data_config_ne.vital` | BLOCKED | 4 (2 high) | 95 | 10% | 29 | - | **YES** |
| `examples/security_lab/nepali/sec_injection_eval_ne.vital` | BLOCKED | 4 (4 high) | 94 | 12.1% | 25 | - | **YES** |
| `examples/security_lab/telugu/sec_auth_account_te.vital` | BLOCKED | 2 (2 high) | 86 | 13.3% | 24 | 15/24 | **YES** |
| `examples/security_lab/telugu/sec_business_workflow_te.vital` | BLOCKED | 2 (1 high) | 75 | 0% | 3 | - | **YES** |
| `examples/security_lab/telugu/sec_data_config_te.vital` | BLOCKED | 5 (2 high) | 96 | 9.6% | 29 | - | **YES** |
| `examples/security_lab/telugu/sec_injection_eval_te.vital` | BLOCKED | 4 (4 high) | 94 | 11.5% | 24 | 18/24 | **YES** |
| `examples/telugu/arithmetic.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/telugu/conditions.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/telugu/hello.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/telugu/loops.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/telugu/task_scheduler_engine.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/telugu/text_statistics_analyzer.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `examples/telugu/warehouse_logistics_tracker.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `src/tests/equiv_bengali.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `src/tests/equiv_english.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `src/tests/equiv_hindi.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `src/tests/equiv_marathi.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `src/tests/equiv_nepali.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
| `src/tests/equiv_telugu.vital` | COMPLETED | 0 (0 high) | 100 | 0% | 0 | - | **NO** |
