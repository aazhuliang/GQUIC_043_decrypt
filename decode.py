
import brotli
import re
import gzip
import pandas as pd
from urllib.parse import unquote

def DeCompress(method:str, data_hex:str):

    if method == "" or data_hex == "":
        return bytes.fromhex(data_hex).decode('utf-8')
    elif method.strip() == "br":
        return brotli.decompress(bytes.fromhex(data_hex)).decode('utf-8');
    elif method.strip() == "gzip":
        return gzip.decompress(bytes.fromhex(data_hex)).decode('utf-8')
        
    return None

def save_dict_array_to_excel(array, filename):
    df = pd.DataFrame(array)
    df.to_excel(filename, index=False)

def GetDataForFile(file_path:str):
    out = []
    with open(file_path, "r") as f:
        for line in f:  
            lines = line.strip().split("___")
            if len(lines) != 4:
                raise
            req_head_hex, req_body_hex, rsp_head_hex, rsp_body_hex = lines

            req_head_hex = req_head_hex.strip() if  len(req_head_hex.strip()) > 0 else ""
            req_body_hex = req_body_hex.strip() if  len(req_body_hex.strip()) > 0 else ""
        
            rsp_head_hex = rsp_head_hex.strip() if  len(rsp_head_hex.strip()) > 0 else ""
            rsp_body_hex = rsp_body_hex.strip() if  len(rsp_body_hex.strip()) > 0 else ""

            rsp_head = bytes.fromhex(rsp_head_hex).decode('utf-8') if len(rsp_head_hex) > 0  else ""
            req_head = bytes.fromhex(req_head_hex).decode('utf-8') if len(req_head_hex) > 0  else ""

            encoding_method_rsp = re.search(r'content-encoding:\s+(.*)', rsp_head)
            encoding_method_req = re.search(r'content-encoding:\s+(.*)', req_head)
            encoding_method_rsp = encoding_method_rsp[1] if encoding_method_rsp != None else ""
            encoding_method_req = encoding_method_req[1] if encoding_method_req != None else ""
            req_body = DeCompress(encoding_method_req, req_body_hex)
            rsp_body = DeCompress(encoding_method_rsp, rsp_body_hex)

            request = f"{req_head}\r\n\r\n{req_body}".strip()
            response = f"{rsp_head}\r\n\r\n{rsp_body}".strip()
            request = unquote(request)
            response = unquote(response)
            out.append({
                "request": request,
                "response": response
            })
    return out
    




if __name__ == "__main__":

    format_data = GetDataForFile("./out.txt")

    save_dict_array_to_excel(format_data, "./test.xlsx")
