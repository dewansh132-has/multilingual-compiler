import json, win32com.client, os, docx
from docx.oxml import parse_xml

def test_arch(json_path, out_docx, width_emu, height_emu):
    with open(json_path, 'r', encoding='utf-8') as f:
        spec = json.load(f)
    
    categories = spec.get('categories', {})
    boxes = spec.get('boxes', [])
    arrows = spec.get('arrows', [])
    box_map = {b['id']: b for b in boxes}
    
    shapes_xml_parts = []
    box_shape_ids = {}
    shape_id = 100
    
    for b in boxes:
        shape_id += 1
        box_shape_ids[b['id']] = shape_id
        cat = categories.get(b.get('category', 'pipeline'), {})
        fill_hex = cat.get('fill', 'E8F0FE')
        stroke_hex = cat.get('stroke', '1A73E8')
        text_color = cat.get('text', '1A73E8')
        stype = b.get('shape_type', 'rect')
        dash_str = '<a:prstDash val="dash"/>' if (b.get('dash') or cat.get('dash') == 'dash') else ''
        
        lines = b['text'].split('\n')
        paragraphs_xml = []
        for line in lines:
            line_esc = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            is_bold = '<w:b/>' if b.get('bold') or line == lines[0] else ''
            paragraphs_xml.append(f"""
              <w:p>
                <w:pPr><w:jc w:val="center"/></w:pPr>
                <w:r>
                  <w:rPr>
                    <w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Nirmala UI"/>
                    {is_bold}
                    <w:sz w:val="{int(b.get('font_size', 8.0) * 2)}"/>
                    <w:color w:val="{text_color}"/>
                  </w:rPr>
                  <w:t>{line_esc}</w:t>
                </w:r>
              </w:p>
            """)
        
        box_xml = f"""
        <wps:wsp>
          <wps:cNvSpPr id="{shape_id}" name="{b['name']}"/>
          <wps:spPr>
            <a:xfrm>
              <a:off x="{b['x']}" y="{b['y']}"/>
              <a:ext cx="{b['width']}" cy="{b['height']}"/>
            </a:xfrm>
            <a:prstGeom prst="{stype}"><a:avLst/></a:prstGeom>
            <a:solidFill><a:srgbClr val="{fill_hex}"/></a:solidFill>
            <a:ln w="19050">
              <a:solidFill><a:srgbClr val="{stroke_hex}"/></a:solidFill>
              {dash_str}
            </a:ln>
          </wps:spPr>
          <wps:txbx>
            <w:txbxContent>
              {''.join(paragraphs_xml)}
            </w:txbxContent>
          </wps:txbx>
          <wps:bodyPr vert="horz" lIns="30000" tIns="30000" rIns="30000" bIns="30000" anchor="ctr"/>
        </wps:wsp>
        """
        shapes_xml_parts.append(box_xml)
        
    for arr in arrows:
        shape_id += 1
        b_from = box_map.get(arr['from'])
        b_to = box_map.get(arr['to'])
        if not b_from or not b_to:
            continue
        
        from_s_id = box_shape_ids.get(arr['from'])
        to_s_id = box_shape_ids.get(arr['to'])
        
        # calculate start/end connection sites
        # connection sites on rect: 0=top, 1=left, 2=bottom, 3=right
        dx = b_to['x'] - b_from['x']
        dy = b_to['y'] - b_from['y']
        
        if abs(dx) > abs(dy):
            if dx > 0:
                x1 = b_from['x'] + b_from['width']
                y1 = b_from['y'] + b_from['height'] // 2
                x2 = b_to['x']
                y2 = b_to['y'] + b_to['height'] // 2
                st_idx = 3
                end_idx = 1
            else:
                x1 = b_from['x']
                y1 = b_from['y'] + b_from['height'] // 2
                x2 = b_to['x'] + b_to['width']
                y2 = b_to['y'] + b_to['height'] // 2
                st_idx = 1
                end_idx = 3
        else:
            if dy > 0:
                x1 = b_from['x'] + b_from['width'] // 2
                y1 = b_from['y'] + b_from['height']
                x2 = b_to['x'] + b_to['width'] // 2
                y2 = b_to['y']
                st_idx = 2
                end_idx = 0
            else:
                x1 = b_from['x'] + b_from['width'] // 2
                y1 = b_from['y']
                x2 = b_to['x'] + b_to['width'] // 2
                y2 = b_to['y'] + b_to['height']
                st_idx = 0
                end_idx = 2
                
        off_x = min(x1, x2)
        off_y = min(y1, y2)
        ext_cx = max(abs(x2 - x1), 1000)
        ext_cy = max(abs(y2 - y1), 1000)
        flip_h = ' flipH="1"' if x2 < x1 else ''
        flip_v = ' flipV="1"' if y2 < y1 else ''
        
        cxn_xml = f"""
        <wps:wsp>
          <wps:cNvSpPr id="{shape_id}" name="Cxn_{arr['from']}_{arr['to']}">
            <a:stCxn id="{from_s_id}" idx="{st_idx}"/>
            <a:endCxn id="{to_s_id}" idx="{end_idx}"/>
          </wps:cNvSpPr>
          <wps:spPr>
            <a:xfrm{flip_h}{flip_v}>
              <a:off x="{off_x}" y="{off_y}"/>
              <a:ext cx="{ext_cx}" cy="{ext_cy}"/>
            </a:xfrm>
            <a:prstGeom prst="line"><a:avLst/></a:prstGeom>
            <a:ln w="12700">
              <a:solidFill><a:srgbClr val="555555"/></a:solidFill>
              <a:headEnd type="triangle" w="med" len="med"/>
            </a:ln>
          </wps:spPr>
          <wps:bodyPr/>
        </wps:wsp>
        """
        shapes_xml_parts.append(cxn_xml)
        
    full_xml = f"""
    <w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
         xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
         xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
         xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup"
         xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">
      <w:r>
        <w:drawing>
          <wp:inline distT="0" distB="0" distL="0" distR="0">
            <wp:extent cx="{width_emu}" cy="{height_emu}"/>
            <wp:docPr id="{shape_id + 50}" name="Architecture Group"/>
            <a:graphic>
              <a:graphicData uri="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup">
                <wpg:wgp>
                  <wpg:cNvGrpSpPr/>
                  <wpg:grpSpPr>
                    <a:xfrm>
                      <a:off x="0" y="0"/><a:ext cx="{width_emu}" cy="{height_emu}"/>
                      <a:chOff x="0" y="0"/><a:chExt cx="{width_emu}" cy="{height_emu}"/>
                    </a:xfrm>
                  </wpg:grpSpPr>
                  {''.join(shapes_xml_parts)}
                </wpg:wgp>
              </a:graphicData>
            </a:graphic>
          </wp:inline>
        </w:drawing>
      </w:r>
    </w:p>
    """
    doc = docx.Document()
    doc._body._body.append(parse_xml(full_xml))
    doc.save(out_docx)
    
    word = win32com.client.Dispatch('Word.Application')
    word.Visible = False
    doc_w = word.Documents.Open(os.path.abspath(out_docx))
    print(f"Verified {out_docx} opened cleanly! Shape count: {len(boxes)} boxes, {len(arrows)} arrows")
    doc_w.Close(False)
    word.Quit()

if __name__ == "__main__":
    test_arch('docs/report_data/architecture_figure1.json', 'docs/test_f1.docx', 5943600, 3200000)
    test_arch('docs/report_data/architecture_figure2.json', 'docs/test_f2.docx', 8229600, 4800000)
