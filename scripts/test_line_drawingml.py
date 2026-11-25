import win32com.client, os, docx
from docx.oxml import parse_xml

doc = docx.Document()
xml = """
<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
     xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
     xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
     xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup"
     xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">
  <w:r>
    <w:drawing>
      <wp:inline distT="0" distB="0" distL="0" distR="0">
        <wp:extent cx="5000000" cy="3000000"/>
        <wp:docPr id="1" name="Group 1"/>
        <a:graphic>
          <a:graphicData uri="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup">
            <wpg:wgp>
              <wpg:cNvGrpSpPr/>
              <wpg:grpSpPr>
                <a:xfrm>
                  <a:off x="0" y="0"/><a:ext cx="5000000" cy="3000000"/><a:chOff x="0" y="0"/><a:chExt cx="5000000" cy="3000000"/>
                </a:xfrm>
              </wpg:grpSpPr>
              <wps:wsp>
                <wps:cNvSpPr id="10" name="Box 1"/>
                <wps:spPr>
                  <a:xfrm><a:off x="500000" y="500000"/><a:ext cx="1000000" cy="800000"/></a:xfrm>
                  <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
                  <a:solidFill><a:srgbClr val="E8F0FE"/></a:solidFill>
                  <a:ln w="19050"><a:solidFill><a:srgbClr val="1A73E8"/></a:solidFill></a:ln>
                </wps:spPr>
                <wps:txbx><w:txbxContent><w:p><w:r><w:t>Box 1</w:t></w:r></w:p></w:txbxContent></wps:txbx>
                <wps:bodyPr/>
              </wps:wsp>
              <wps:wsp>
                <wps:cNvSpPr id="11" name="Box 2"/>
                <wps:spPr>
                  <a:xfrm><a:off x="2500000" y="500000"/><a:ext cx="1000000" cy="800000"/></a:xfrm>
                  <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
                  <a:solidFill><a:srgbClr val="E8F0FE"/></a:solidFill>
                  <a:ln w="19050"><a:solidFill><a:srgbClr val="1A73E8"/></a:solidFill></a:ln>
                </wps:spPr>
                <wps:txbx><w:txbxContent><w:p><w:r><w:t>Box 2</w:t></w:r></w:p></w:txbxContent></wps:txbx>
                <wps:bodyPr/>
              </wps:wsp>
              <wps:wsp>
                <wps:cNvSpPr id="12" name="Line 1">
                  <a:stCxn id="10" idx="3"/>
                  <a:endCxn id="11" idx="1"/>
                </wps:cNvSpPr>
                <wps:spPr>
                  <a:xfrm><a:off x="1500000" y="900000"/><a:ext cx="1000000" cy="0"/></a:xfrm>
                  <a:prstGeom prst="line"><a:avLst/></a:prstGeom>
                  <a:ln w="19050">
                    <a:solidFill><a:srgbClr val="555555"/></a:solidFill>
                    <a:headEnd type="triangle" w="med" len="med"/>
                  </a:ln>
                </wps:spPr>
                <wps:bodyPr/>
              </wps:wsp>
            </wpg:wgp>
          </a:graphicData>
        </a:graphic>
      </wp:inline>
    </w:drawing>
  </w:r>
</w:p>
"""
doc._body._body.append(parse_xml(xml))
test_path = os.path.abspath('docs/test_line.docx')
doc.save(test_path)
word = win32com.client.Dispatch('Word.Application')
word.Visible = False
doc_word = word.Documents.Open(test_path)
print('Opened cleanly! InlineShape count:', doc_word.InlineShapes.Count)
doc_word.Close(False)
word.Quit()
