import os
from PIL import Image

ORIG_DIR = "docs/report_assets/screenshots"
CROP_DIR = "docs/report_assets/screenshots/cropped"
os.makedirs(CROP_DIR, exist_ok=True)

# 1. Figure 3: Telugu Clean Demo Editor + Code Health (x: 350 to 2558, y: 70 to 1150)
im3 = Image.open(os.path.join(ORIG_DIR, "Screenshot 2026-11-18 235051.png"))
# crop editor + health panel
crop3 = im3.crop((350, 70, 2558, 1150))
crop3.save(os.path.join(CROP_DIR, "fig3_clean_telugu_workspace.png"))
print("Saved fig3 crop:", crop3.size)

# 2. Figure 4: Telugu Unsafe Demo C Editor + Code Health degraded (x: 350 to 2558, y: 70 to 1150)
im4 = Image.open(os.path.join(ORIG_DIR, "Screenshot 2026-11-18 235209.png"))
crop4 = im4.crop((350, 70, 2558, 1150))
crop4.save(os.path.join(CROP_DIR, "fig4_vulnerable_telugu_workspace.png"))
print("Saved fig4 crop:", crop4.size)

# 3. Figure 5: Stage 11 Gate Block - Pipeline Strip & Findings Drawer
im5 = Image.open(os.path.join(ORIG_DIR, "Screenshot 2026-11-18 235305.png"))
# The pipeline strip and central security drawer
crop5 = im5.crop((350, 60, 2558, 1150))
crop5.save(os.path.join(CROP_DIR, "fig5_stage11_gate_block_drawer.png"))
print("Saved fig5 crop:", crop5.size)

# 4. Figure 6: Fix All Modal Dialog (focused on the centered modal)
im6 = Image.open(os.path.join(ORIG_DIR, "Screenshot 2026-11-18 235322.png"))
# modal dialog is located from x: 440 to 2550, y: 95 to 1205
crop6 = im6.crop((440, 95, 2550, 1205))
crop6.save(os.path.join(CROP_DIR, "fig6_fix_all_modal_diff.png"))
print("Saved fig6 crop:", crop6.size)

# 5. Figure 7: Post-remediation Execution & Stage 14 Audit Output
im7 = Image.open(os.path.join(ORIG_DIR, "Screenshot 2026-11-18 235412.png"))
crop7 = im7.crop((350, 60, 2546, 1150))
crop7.save(os.path.join(CROP_DIR, "fig7_verified_post_fix_output.png"))
print("Saved fig7 crop:", crop7.size)

# 6. Figure 8: Restored Code Health Panel (already perfectly cropped)
im8 = Image.open(os.path.join(ORIG_DIR, "Screenshot 2026-11-18 235721.png"))
im8.save(os.path.join(CROP_DIR, "fig8_restored_code_health_panel.png"))
print("Saved fig8 crop:", im8.size)
