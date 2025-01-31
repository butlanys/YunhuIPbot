from flask import Flask, request, jsonify
import json
import requests
import threading
import subprocess
import setproctitle
import re
import time

app = Flask(__name__)

url = "https://chat-go.jwzhd.com/open-apis/v1/bot/send?token=xxx"
ipdata_api_key = ""

# 定义全局的翻译映射
translate_map = {
    "ip": "IP 地址",
    "is_eu": "是否为欧盟国家",
    "city": "城市",
    "region": "地区",
    "region_code": "地区代码",
    "region_type": "地区类型",
    "country_name": "国家",
    "country_code": "国家代码",
    "continent_name": "洲",
    "continent_code": "洲代码",
    "latitude": "纬度",
    "longitude": "经度",
    "postal": "邮编",
    "calling_code": "区号",
    "flag": "国旗",
    "emoji_flag": "表情符号国旗",
    "emoji_unicode": "Unicode 表情符号",
    "asn": "自治系统号",
    "name": "名称",
    "domain": "域名",
    "route": "路由",
    "type": "类型",
    "languages": "语言",
    "currency": "货币",
    "code": "代码",
    "symbol": "符号",
    "native": "本地",
    "plural": "复数",
    "time_zone": "时区",
    "abbr": "缩写",
    "offset": "偏移量",
    "is_dst": "是否为夏令时",
    "current_time": "当前时间",
    "threat": "威胁情报",
    "is_tor": "是否为 Tor 节点",
    "is_icloud_relay": "是否为 iCloud 中继",
    "is_proxy": "是否为代理",
    "is_datacenter": "是否为数据中心",
    "is_anonymous": "是否为匿名",
    "is_known_attacker": "是否为已知攻击者",
    "is_known_abuser": "是否为已知滥用者",
    "is_threat": "是否存在威胁",
    "is_bogon": "是否为保留地址",
    "blocklists": "黑名单",
    "count": "查询次数",
    # WHOIS 字段翻译
    "Domain Name:": "域名:",
    "Registry Domain ID:": "注册域名 ID:",
    "Registrar WHOIS Server:": "注册商 WHOIS 服务器:",
    "Registrar URL:": "注册商网址:",
    "Updated Date:": "更新日期:",
    "Creation Date:": "创建日期:",
    "Registry Expiry Date:": "注册到期日期:",
    "Registrar:": "注册商:",
    "Registrar IANA ID:": "注册商 IANA ID:",
    "Registrar Abuse Contact Email:": "注册商滥用联系邮箱:",
    "Registrar Abuse Contact Phone:": "注册商滥用联系电话:",
    "Domain Status:": "域名状态:",
    "Registry Registrant ID:": "注册人 ID:",
    "Registrant Name:": "注册人姓名:",
    "Registrant Organization:": "注册人组织:",
    "Registrant Street:": "注册人街道地址:",
    "Registrant City:": "注册人城市:",
    "Registrant State/Province:": "注册人省/州:",
    "Registrant Postal Code:": "注册人邮政编码:",
    "Registrant Country:": "注册人国家:",
    "Registrant Phone:": "注册人电话:",
    "Registrant Phone Ext:": "注册人电话分机:",
    "Registrant Fax:": "注册人传真:",
    "Registrant Fax Ext:": "注册人传真分机:",
    "Registrant Email:": "注册人电子邮件:",
    "Registry Admin ID:": "管理员 ID:",
    "Admin Name:": "管理员姓名:",
    "Admin Organization:": "管理员组织:",
    "Admin Street:": "管理员街道地址:",
    "Admin City:": "管理员城市:",
    "Admin State/Province:": "管理员省/州:",
    "Admin Postal Code:": "管理员邮政编码:",
    "Admin Country:": "管理员国家:",
    "Admin Phone:": "管理员电话:",
    "Admin Phone Ext:": "管理员电话分机:",
    "Admin Fax:": "管理员传真:",
    "Admin Fax Ext:": "管理员传真分机:",
    "Admin Email:": "管理员电子邮件:",
    "Registry Tech ID:": "技术联系人 ID:",
    "Tech Name:": "技术联系人姓名:",
    "Tech Organization:": "技术联系人组织:",
    "Tech Street:": "技术联系人街道地址:",
    "Tech City:": "技术联系人城市:",
    "Tech State/Province:": "技术联系人省/州:",
    "Tech Postal Code:": "技术联系人邮政编码:",
    "Tech Country:": "技术联系人国家:",
    "Tech Phone:": "技术联系人电话:",
    "Tech Phone Ext:": "技术联系人电话分机:",
    "Tech Fax:": "技术联系人传真:",
    "Tech Fax Ext:": "技术联系人传真分机:",
    "Tech Email:": "技术联系人电子邮件:",
    "Name Server:": "域名服务器:",
    "DNSSEC:": "DNSSEC:",
    "URL of the ICANN Whois Inaccuracy Complaint Form:": "ICANN Whois 错误投诉表单网址:",
    ">>> Last update of WHOIS database:": "WHOIS 数据库最后更新时间:",
    "For more information on Whois status codes, please visit": "有关 Whois 状态代码的更多信息，请访问",
    "NetRange:": "网络范围:",
    "CIDR:": "CIDR:",
    "NetName:": "网络名称:",
    "NetHandle:": "网络句柄:",
    "Parent:": "上级网络:",
    "NetType:": "网络类型:",
    "OriginAS:": "原始 AS:",
    "Organization:": "组织:",
    "RegDate:": "注册日期:",
    "Updated:": "更新日期:",
    "Comment:": "备注:",
    "Ref:": "参考:",
    "OrgName:": "组织名称:",
    "OrgId:": "组织 ID:",
    "Address:": "地址:",
    "City:": "城市:",
    "StateProv:": "省/州:",
    "PostalCode:": "邮政编码:",
    "Country:": "国家:",
    "OrgTechHandle:": "技术联系人句柄:",
    "OrgTechName:": "技术联系人姓名:",
    "OrgTechPhone:": "技术联系人电话:",
    "OrgTechEmail:": "技术联系人电子邮件:",
    "OrgTechRef:": "技术联系人参考:",
    "OrgAbuseHandle:": "滥用联系人句柄:",
    "OrgAbuseName:": "滥用联系人姓名:",
    "OrgAbusePhone:": "滥用联系人电话:",
    "OrgAbuseEmail:": "滥用联系人电子邮件:",
    "OrgAbuseRef:": "滥用联系人参考:",
    "RTechHandle:": "路由技术联系人句柄:",
    "RTechName:": "路由技术联系人姓名:",
    "RTechPhone:": "路由技术联系人电话:",
    "RTechEmail:": "路由技术联系人电子邮件:",
    "RTechRef:": "路由技术联系人参考:",
    "RAbuseHandle:": "路由滥用联系人句柄:",
    "RAbuseName:": "路由滥用联系人姓名:",
    "RAbusePhone:": "路由滥用联系人电话:",
    "RAbuseEmail:": "路由滥用联系人电子邮件:",
    "RAbuseRef:": "路由滥用联系人参考:",
}


def translate_and_format_ipdata_response(response_json):
    """将 IPData API 的英文响应翻译成中文，并格式化为易读的字符串。"""

    def translate_value(value):
        if isinstance(value, dict):
            return "\n".join(
                f"  - {translate_map.get(k, k)}: {translate_value(v)}" for k, v in value.items()
            )
        elif isinstance(value, list):
            return "\n".join(f"  - {translate_value(item)}" for item in value)
        else:
            return str(value)

    formatted_text = "\n".join(
        f"{translate_map.get(key, key)}: {translate_value(value)}"
        for key, value in response_json.items()
    )

    return formatted_text


def translate_whois(whois_text):
    """将 whois 信息翻译成中文，并删除 # 号行, NOTICE 和 TERMS OF USE。"""

    translated_lines = []
    skip_line = False
    for line in whois_text.splitlines():
        # 删除 # 号行
        if line.strip().startswith("#"):
            continue

        # 跳过 NOTICE 和 TERMS OF USE 部分
        if "NOTICE:" in line or "TERMS OF USE:" in line:
            skip_line = True
        if skip_line and (line.strip() == "" or line.strip().startswith(">>>")):
            skip_line = False
            continue
        if skip_line:
            continue

        # 删除包含 REDACTED FOR PRIVACY 的行
        if "REDACTED FOR PRIVACY" in line:
            continue

        # 使用更精确的正则表达式匹配需要翻译的字段
        match = re.match(r"^(.+?:)\s*(.*)$", line.strip())
        if match:
            key = match.group(1).strip()
            value = match.group(2).strip()
            # 翻译 key 并拼接
            translated_line = f"{translate_map.get(key, key)} {value}"
        else:
            translated_line = line
        translated_lines.append(translated_line)

    return "\n".join(translated_lines)


def yhchat_push(recvId, recvType, contentType, text):
    print(f"回复内容{text}")
    payload = json.dumps({
        "recvId": recvId,
        "recvType": recvType,
        "contentType": contentType,
        "content": {
            "text": text,
            "buttons": [
                [
                    {
                        "text": "复制",
                        "actionType": 2,
                        "value": text
                    },
                ]
            ]
        }
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    # print(response.text)
    return response.text

def add_code_block(value):
    """使用 Markdown 的代码块包裹文本。"""
    return f"```\n{value}\n```"


def dispose_address(recvType, recvId, contentType, text, commandId):
    print(f"内容：{text}")

    if commandId == 533:  # IP地址查询
        text_ok = subprocess.check_output(f"/root/ip_bot/nali {text}", shell=True).decode().strip()
        yhchat_push(recvId, recvType, contentType, text_ok)
    elif commandId == 534:  # whois查询
        try:
            whois_output = subprocess.check_output(f"whois {text}", shell=True).decode().strip()
            translated_whois = translate_whois(whois_output)
            yhchat_push(recvId, recvType, contentType, translated_whois)
        except subprocess.CalledProcessError as e:
            print(f"whois 查询出错: {e}")
            yhchat_push(recvId, recvType, contentType, f"查询 {text} 的 whois 信息出错。")

    elif commandId == 766:  # IP ANS查询
        try:
            ipdata_response = requests.get(f"https://api.ipdata.co/{text}?api-key={ipdata_api_key}")
            ipdata_response.raise_for_status()

            formatted_response = translate_and_format_ipdata_response(ipdata_response.json())
            yhchat_push(recvId, recvType, contentType, formatted_response)

        except requests.exceptions.RequestException as e:
            print(f"IPData API 请求出错: {e}")
            yhchat_push(recvId, recvType, contentType, "查询 IP 信息出错，请稍后再试。")
    elif commandId == 767:  # NextTrace
        try:
            # 执行 NextTrace 命令并获取输出
            nexttrace_output = subprocess.check_output(
                f"/usr/local/bin/nexttrace {text}", shell=True
            ).decode()

            # 使用正则表达式去除 ANSI 转义序列
            ansi_escape = re.compile(r"\x1b\[[0-9;]*[mG]")
            text_ok = ansi_escape.sub("", nexttrace_output)

            # 使用 Markdown 代码块包裹输出
            text_ok = add_code_block(text_ok)

            yhchat_push(recvId, recvType, contentType, text_ok)

        except subprocess.CalledProcessError as e:
            print(f"NextTrace 执行出错: {e}")
            yhchat_push(recvId, recvType, contentType, f"NextTrace 执行出错: {e}")
    
    elif commandId == 773: #ip段
        headers = {'User-Agent': 'headers=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0'}
        text_ok=requests.get(f"http://ipblock.chacuo.net/down/t_txt=c_{text}",headers=headers)
        cleaned_text = re.sub(r'<pre>\s*|\s*</pre>', '', text_ok.text)
        
        # 将IP段列表按行分割
        ip_lines = cleaned_text.splitlines()
        
        # 设置每条消息最多包含的IP行数
        max_lines_per_message = 60
        
        # 分段发送消息
        for i in range(0, len(ip_lines), max_lines_per_message):
            # 获取当前消息段的IP行
            message_lines = ip_lines[i:i + max_lines_per_message]
            # 将IP行拼接成字符串
            message_text = "\n".join(message_lines)
            # 发送消息
            yhchat_push(recvId, recvType, contentType, message_text)
            
            time.sleep(0.5)

    else:
        text_ok = subprocess.check_output(f"/root/ip_bot/nali {text}", shell=True).decode().strip()
        yhchat_push(recvId, recvType, contentType, text_ok)


# 处理消息函数，解析消息并调用推送消息函数
def handle_message(parsed_json):
    senderType_tmp = parsed_json['event']['chat']['chatType']

    if senderType_tmp == "bot":
        senderType = "user"
        print(f"类型：{senderType}")
        senderId = parsed_json['event']['sender']['senderId']
        print(f"用户ID：{senderId}")
        commandId = parsed_json['event']['message']['commandId']
        print(f"消息ID：{commandId}")
        text = parsed_json['event']['message']['content']['text']  # 处理用户输入的文本

        threading.Thread(target=dispose_address, args=(senderType, senderId, "markdown", text, commandId)).start()


@app.route('/yhchat', methods=['POST'])
def receive_message():
    try:
        json_data = request.get_json()
        handle_message(json_data)
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        print("Error:", e)
        return jsonify({'status': 'error', 'message': str(e)}), 500


if __name__ == '__main__':
    setproctitle.setproctitle("yhchatBot_ip-bot")
    app.run(host='0.0.0.0', port=56668)
