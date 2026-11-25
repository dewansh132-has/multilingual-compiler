# -*- coding: utf-8 -*-
import os
import docx
from docx.oxml import parse_xml
import win32com.client

doc = docx.Document()
p = doc.add_paragraph('Test DrawingML shape paragraph')

shape_xml = """
<w:r xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
     xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
     xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
     xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup"
     xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">
  <w:drawing>
    <wp:inline distT="0" distB="0" distL="0" distR="0">
      <wp:extent cx="5486400" cy="2743200"/>
      <wp:effectExtent l="0" t="0" r="0" b="0"/>
      <wp:docPr id="1" name="Group 1"/>
      <wp:cNvGraphicFramePr/>
      <a:graphic>
        <a:graphicData uri="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup">
          <wpg:wgp>
            <wpg:cNvGrpSpPr/>
            <wpg:grpSpPr>
              <a:xfrm>
                <a:off x="0" y="0"/>
                <a:ext cx="5486400" cy="2743200"/>
                <a:chOff x="0" y="0"/>
                <a:chExt cx="5486400" cy="2743200"/>
              </a:xfrm>
            </wpg:grpSpPr>
            <wps:wsp>
              <wps:cNvSpPr id="2" name="Box1"/>
              <wps:spPr>
                <a:xfrm>
                  <a:off x="100000" y="100000"/>
                  <a:ext cx="2500000" cy="1200000"/>
                </a:xfrm>
                <a:prstGeom prst="roundRect">
                  <a:avLst/>
                </a:prstGeom>
                <a:solidFill>
                  <a:srgbClr val="E8F0FE"/>
                </a:solidFill>
                <a:ln w="19050">
                  <a:solidFill>
                    <a:srgbClr val="1A73E8"/>
                  </a:solidFill>
                </a:ln>
              </wps:spPr>
              <wps:txbx>
                <w:txbxContent>
                  <w:p>
                    <w:pPr>
                      <w:jc w:val="center"/>
                    </w:pPr>
                    <w:r>
                      <w:rPr>
                        <w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>
                        <w:b/>
                        <w:sz w:val="20"/>
                        <w:color w:val="1A73E8"/>
                      </w:rPr>
                      <w:t>VITAL Stage Box</w:t>
                    </w:r>
                  </w:p>
                </w:txbxContent>
              </wps:txbx>
              <wps:bodyPr vert="horz" lIns="91440" tIns="91440" rIns="91440" bIns="91440" anchor="ctr"/>
            </wps:wsp>
          </wpg:wgp>
        </a:graphicData>
      </a:graphic>
    </wp:inline>
  </w:drawing>
</w:r>
"""

r_elem = parse_xml(shape_xml)
p._p.append(r_elem)

os.makedirs('docs', exist_ok=True)
test_path = os.path.abspath('docs/test_shape.docx')
doc.save(test_path)
print(f'Saved test docx to: {test_path}')

# Test opening with Word COM
word = win32com.client.Dispatch('Word.Application')
word.Visible = False
try:
    doc_word = word.Documents.Open(test_path)
    print('SUCCESS: Word opened the file cleanly without repair prompts!')
    print('Shapes count:', doc_word.Shapes.Count)
    doc_word.Close(False)
finally:
    word.Quit()
