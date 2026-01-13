from scapy.all import *
import copy
from datetime import datetime, timedelta
# import pandas as pd
import netifaces
import pymongo
from pymongo.errors import ConnectionFailure, ConfigurationError, PyMongoError
import os
from pydantic import BaseModel, Field
import threading, time
from collections import Counter

# Thread Lock
lock = threading.Lock()

# DB 연결
DB_USER = os.getenv('DB_USER')
DB_PASS = os.getenv('DB_PASS')
try:
    conn = pymongo.MongoClient((f'mongodb+srv://{DB_USER}:{DB_PASS}@ip-info.sc0rnyd.mongodb.net/?appName=ip-info'))
    print('DB Connected!')
except (ConnectionFailure, ConfigurationError) as e:
    print(f'DB Connection Error: {e}')
    conn = None

# DB 저장할 데이터 스키마
class AttackData(BaseModel):
        attack_type: str
        src_ip: str
        dst_ip: str
        protocol: str
        timestamp: str = Field(default_factory=lambda: datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        extra_data: dict | None = None

# 프로토콜 정보
protocol = {1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
            }

# 알려진 포트 정보
port = {20: 'FTP-Data',
        21: 'FTP-Control',
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        443: 'HTTPS',
        3306: 'DBMS'
        }

# ICMP 타입, 코드 설명
icmp_info = {0: {'type': 'Echo Reply'},
             3: {'type': 'Unreachable',
                 0: 'Network',
                 1: 'Host',
                 2: 'Protocol',
                 3: 'Port'},
             5: {'type': 'Redirect',
                 0: 'Network',
                 1: 'Host'},
             8: {'type': 'Echo Request'},
             11: {'type': 'Time Exceed',
                  0: 'TTL',
                  1: 'Reassemble'},
             12: {'type': 'Param Problem',
                  0: 'Incorrect Header',
                  1: 'No Need Option',
                  2: 'Wrong Length'}
            }

# TCP Flag 정보
flags_info = {
        '': 'No Flag (0)',
        'A': 'ACK',
         'S': 'SYN',
         'R': 'RST',
         'P': 'PSH',
         'U': 'URG',
         'F': 'FIN',
         'RA': 'RST+ACK',
         'SA': 'SYN+ACK',
         'PA': 'PSH+ACK'}

# 프로토콜 이름 반환 함수
def get_proto_name(proto_num):
    return protocol.get(proto_num, 'UNKNOWN')

# 포트 이름 반환 함수
def get_port_name(port_num):
    return port.get(port_num, None)

# ICMP 타입, 코드 반환 함수
def get_icmp_info(itype, icode=None):
    icmp_t_c_info = icmp_info.get(itype)

    # icmp_info 딕셔너리에 없는 경우
    if icmp_t_c_info is None:
        return None, None
    
    # type 값 매핑
    icmp_type = icmp_t_c_info['type']

    # type은 있는데 code값이 None이거나 딕셔너리에 없는 경우
    if icode is None or icode not in icmp_t_c_info:
        return icmp_type, "Unknown Code"

    # code도 있는 경우
    icmp_code = icmp_t_c_info[icode]
    return icmp_type, icmp_code

# TCP Flag 반환 함수
def get_flag_type(flag):
    return flags_info.get(flag)

# 사용자의 현재 IP 반환 함수
def get_user_ip():
    # 게이트웨이 정보 가져오기
    gateway = netifaces.gateways()
    default_gateway = gateway.get('default')

    # AF_INET 정보 == IPv4 정보
    if default_gateway and netifaces.AF_INET in default_gateway:
        ip4_key = netifaces.AF_INET
        interface = default_gateway[ip4_key][1] # ex) ens33, eth0 등

        # interface에 관한 주소 정보를 addresses에 저장
        addresses = netifaces.ifaddresses(interface)
        if ip4_key in addresses:
            # addr 값이 사용자의 IP 주소
            return addresses[ip4_key][0]['addr']
    return None

# 탐지를 실행하는 함수
def detect_attack(packet, user_ip):
    detect_land(packet)
    detect_scan_DoS(packet, user_ip)

# 로그파일에 탐지 정보 기록하는 함수
def write_log(filename, message):
    with open(filename, 'a', encoding='utf-8') as file:
        file.write(message+'\n')

# DB 저장 함수
def post_DB(ip_key, control, attack_type, data):
    if conn is None:
        return
    
    try:
        db = conn.IRIS_DATABASE
        coll = db[f'{attack_type}_attack']
        # insert와 update를 구분하여 DB 저장
        if control == "insert":
            result = coll.insert_one(data.model_dump())
            inserted_data_id = result.inserted_id
            return inserted_data_id
        elif control == "update":
            coll.update_one({'_id': ip_key}, {'$set': data})
    except PyMongoError as e:
        print(f'DB Insert/Update Error: {e}')


# -----------LAND ATTACK-----------
# LandAttack 공통 수행 함수
def common_land(ip, sport, dport, sport_name, dport_name, proto_name, date):
    attack_proto = proto_name.upper()
    init_attack_info(ip.src, "LANDATTACK", attack_proto)

    data = AttackData(
                attack_type="LandAttack",
                src_ip=ip.src,
                dst_ip=ip.dst,
                protocol=proto_name,
                extra_data={
                    "sport": sport,
                    "dport": dport
                }
            )
    # DB에 도큐먼트 ID 값이 존재하지 않으면 저장
    if attack_info[ip.src]['LANDATTACK'][attack_proto]['attack_ip_id'] is None:
        attack_info[ip.src]['LANDATTACK'][attack_proto]['attack_ip_id'] = post_DB(None, "insert", "land", data)
    
    # 우분투 파일에 로깅
    write_log('land_attack.log', f'{date} Protocol: {ip.proto}({proto_name}) src: {ip.src} dst: {ip.dst} sport: {sport}({sport_name}) dport: {dport}({dport_name}) msg: LAND-ATTACK')

# LandAttack 탐지 함수
def detect_land(packet):
    if not packet.haslayer(IP):
        return
    
    ip = packet['IP']
    proto_name = get_proto_name(ip.proto)
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # TCP LandAttack
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        
        if ip.src == ip.dst:
            print("LandAttack! - TCP")
            common_land(ip, tcp.sport, tcp.dport, 
                        get_port_name(tcp.sport), 
                        get_port_name(tcp.dport), 
                        proto_name, date)
        return
    
    # UDP LandAttack
    if packet.haslayer(UDP):
        udp = packet[UDP]
        
        if ip.src == ip.dst:
            print("LandAttack! - UDP")
            common_land(ip, udp.sport, udp.dport, 
                        get_port_name(udp.sport), 
                        get_port_name(udp.dport), 
                        proto_name, date)
        return
    return
# ---------------------------------

# -----Port Scan / DoS ATTACK------
ip_list = {}        # IP 별 정보를 저장 (2초가 지난 패킷은 처분)
tcp_ports = {}      # TCP 포트 정보를 저장 (ip_list에 들어 있는 패킷 중 TCP 패킷에 대한 dport 포트 정보)
udp_ports = {}      # UDP 포트 정보를 저장 (ip_list에 들어 있는 패킷 중 UDP 패킷에 대한 dport 포트 정보)

# PortScan/DoS 공통 수행 함수 - DB 저장 및 로그파일 생성
def common_scan_DoS(ip, proto_name, attack_type, extra=None):
    VALID_ATTACKS = {'DOS', 'PORTSCAN'}
    if attack_type not in VALID_ATTACKS:
        raise ValueError("Invalid attack type!")
    
    attack_proto = proto_name.upper()
    attack_type_lower = attack_type.lower()
    
    data = AttackData(
        attack_type=attack_type,
        src_ip=ip.src,
        dst_ip=ip.dst,
        protocol=proto_name,
        extra_data=extra
    )

    # 로깅을 위한 변수 atk_type
    if attack_type == 'PORTSCAN':
        atk_type = 'scan'
    else:
        atk_type = 'flood'

    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # need_insert는 DB에 insert 후, id를 반환해야 한다는 의미
    need_insert = False
    with lock:
        if attack_info[ip.src][attack_type][attack_proto]['attack_ip_id'] is None:
            attack_info[ip.src][attack_type][attack_proto]['attack_ip_id'] = 'PENDING'
            need_insert = True

    if need_insert:
        db_id = post_DB(None, "insert", attack_type_lower, data)
        with lock:
            attack_info[ip.src][attack_type][attack_proto]['attack_ip_id'] = db_id

    # 우분투 파일에 로깅
    if proto_name == 'TCP':
        write_log(f'{attack_type_lower}_attack.log', f"{date} Protocol: {ip.proto}({proto_name}), src: {ip.src}, dst: {ip.dst}, sport: {extra['sport']}({extra['sport_name']}), dport: {extra['dport']}({extra['dport_name']}), msg: {attack_type} Attack with {extra['type_rate']}% {extra[f'{atk_type}_type']} {atk_type.upper()}!")
    elif proto_name == 'UDP':
        write_log(f'{attack_type_lower}_attack.log', f"{date} Protocol: {ip.proto}({proto_name}), src: {ip.src}, dst: {ip.dst}, sport: {extra['sport']}({extra['sport_name']}), dport: {extra['dport']}({extra['dport_name']}), msg: {attack_type} Attack with UDP {atk_type.upper()}!")
    else:
        write_log(f'{attack_type_lower}_attack.log', f"{date} Protocol: {ip.proto}({proto_name}), src: {ip.src}, dst: {ip.dst}, type: {extra['icmp_type']}, code: {extra['icmp_code']}, msg: {attack_type} Attack with ICMP {atk_type.upper()}!")

#  패킷 리스트 및 길이 반환 함수
def count_packet(ip, packet, proto, second):
    now_time = int(datetime.now().timestamp())

    # ip 별, ip_list 초기화
    if ip.src not in ip_list:
        ip_list[ip.src] = {"TCP": [], "UDP": [], "ICMP": []}

    ip_list[ip.src][proto].append({'pkt': packet, 'time': now_time})
    # ip_list[ip][프로토콜]에 저장한지 2초가 지난 패킷은 폐기
    ip_list[ip.src][proto] = [item for item in ip_list[ip.src][proto] if now_time - item['time'] <= second]

    return len(ip_list[ip.src][proto])

# Flag 정보 반환 함수 - TCP 한해서만 수행
def return_flag(dos_flags):
    flags = [str(item['pkt'][TCP].flags) for item in dos_flags["TCP"] if item['pkt'].haslayer(TCP)]
    if not flags:
        return None
    
    counter = Counter(flags)
    top_flag, freq = counter.most_common(1)[0]
    
    result_flag_info = {
        'total_count': len(flags),
        'top_flag': top_flag,
        'freq': freq
    }

    return result_flag_info

# Port Scan Extra 반환 함수 - TCP 한해서만 수행
def return_tcp_port_scan(tcp, flag_info):
    extra = None
    if flag_info['total_count'] > 0:
        top_flag = get_flag_type(flag_info['top_flag']) # str
        if top_flag is None:
            top_flag = ''
        flag_count = flag_info['total_count']
        top_flag_rate = round((flag_info['freq'] / flag_count) * 100)
        extra = {
            "sport": tcp.sport,
            "sport_name": get_port_name(tcp.sport),
            "dport": tcp.dport,
            "dport_name": get_port_name(tcp.dport),
            "scan_type": top_flag,
            "type_rate": f'{top_flag_rate}%'
        }
    return extra

# DoS Extra 반환 함수 - TCP 한해서만 수행
def return_tcp_dos(tcp, flag_info):
    extra = None
    if flag_info['total_count'] > 0:
        top_flag = get_flag_type(flag_info['top_flag']) # str
        if top_flag is None:
            top_flag = ''
        flag_count = flag_info['total_count']
        top_flag_rate = round((flag_info['freq'] / flag_count) * 100)
        extra = {
            "sport": tcp.sport,
            "sport_name": get_port_name(tcp.sport),
            "dport": tcp.dport,
            "dport_name": get_port_name(tcp.dport),
            "flood_type": top_flag,
            "type_rate": f'{top_flag_rate}'
        }
    return extra

# 공격 탐지 후, 5초의 쿨다운 시간동안 상태 유예
cooldown = timedelta(seconds=5)
# DoS 공격 종료를 1초마다 확인하는 함수
def dos_end_timer():
    while True:
        now = datetime.now()
        for ip in list(dos_status.keys()):
            for proto in ("TCP", "UDP", "ICMP"):
                attack_id = None
                attack_start = None
                total_count = None
                with lock:
                    status = dos_status[ip][proto]
                    if not status["is_attack"]:
                        continue
                    last = status["last_packet_time"]
                    # 공격을 탐지하고 5초가 지났을 때, 공격 종료
                    if last and now - last >= cooldown:
                        print(f"DOS END! - {proto}")

                        attack_id = attack_info[ip]["DOS"][proto]["attack_ip_id"]
                        attack_start = attack_info[ip]["DOS"][proto]["start"]
                        total_count = status["total_count"]

                        status["is_attack"] = False
                        status["total_count"] = 0
                        attack_info[ip]["DOS"][proto]["attack_ip_id"] = None
                        attack_info[ip]["DOS"][proto]["start"] = None
                        attack_info[ip]["DOS"][proto]["end"] = None

                        if ip in ip_list:
                            ip_list[ip][proto] = []
                        if proto == 'TCP' and ip in tcp_ports:
                            tcp_ports[ip]['ports'].clear()
                        if proto == 'UDP' and ip in udp_ports:
                            udp_ports[ip]['ports'].clear()
                # 공격이 완전히 종료된 시점에 해당 id를 이용하여 DB 업데이트
                if attack_id:       
                    update_data = {
                        "attack_start": attack_start,
                        "attack_end": now.strftime("%Y-%m-%d %H:%M:%S"),
                        "attack_count": total_count
                    }
                    post_DB(attack_id, "update", "dos", update_data)
        time.sleep(1)

# PortScan 공격 종료를 1초마다 확인하는 함수
def portscan_end_timer():
    while True:
        now = datetime.now()
        for ip in list(portscan_status.keys()):
            for proto in ("TCP", "UDP"):
                # 일반적인 종료는 force값을 생략하여 False로 간주
                end_portscan(ip, proto, now)
        time.sleep(1)

# PortScan 일반 종료 및 강제 종료 공통 함수
def end_portscan(ip, proto, now, force=False):
    attack_id = None
    attack_start = None
    total_count = None
    min_port = None
    max_port = None
    
    with lock:
        status = portscan_status[ip][proto]
        if not status["is_attack"]:
            return
        last = status["last_packet_time"]

        # force가 True일 때, 강제종료, False일 때, 쿨다운 적용
        if not force:
            if not (last and now - last >= cooldown):
                return
        
        print(f"PORTSCAN END! - {proto}")
                            
        min_port = status['min_port']
        max_port = status['max_port']
        attack_id = attack_info[ip]["PORTSCAN"][proto]["attack_ip_id"]
        attack_start = attack_info[ip]["PORTSCAN"][proto]["start"]
        total_count = status["total_count"]
                        
        status["is_attack"] = False
        status["total_count"] = 0
        status['min_port'] = None
        status['max_port'] = None
        attack_info[ip]["PORTSCAN"][proto]["attack_ip_id"] = None
        attack_info[ip]["PORTSCAN"][proto]["start"] = None
        attack_info[ip]["PORTSCAN"][proto]["end"] = None
        if not force:
            if ip in ip_list:
                ip_list[ip][proto] = []
        if proto == 'TCP' and ip in tcp_ports:
            tcp_ports[ip]['ports'].clear()
        if proto == 'UDP' and ip in udp_ports:
            udp_ports[ip]['ports'].clear()

        # saved가 True이면 이미 도큐먼트 업데이트를 완료했다는 의미
        if status['saved'] == True:
            return
        status['saved'] = True

    if attack_id:
        update_data = {
            "attack_start": attack_start,
            "attack_end": now.strftime("%Y-%m-%d %H:%M:%S"),
            "attack_count": total_count,
            "scan_port_range": f'{min_port}-{max_port}'
        }

        try:
            post_DB(attack_id, "update", "portscan", update_data)
        except Exception:
            with lock:
                portscan_status[ip][proto]['saved'] = False
            raise

# ip 별, attack_info Initialize 및 공격 정보 저장
def init_attack_info(ip, attack_type, attack_proto):
    with lock:
        if ip not in attack_info:
            attack_info[ip] = {
                "DOS": {
                    "TCP": {
                        "attack_ip_id": None,
                        "start": None,
                        "end": None,
                    },
                    "UDP": {
                        "attack_ip_id": None,
                        "start": None,
                        "end": None,
                    },
                    "ICMP": {
                        "attack_ip_id": None,
                        "start": None,
                        "end": None,
                    }
                },
                "PORTSCAN": {
                    "TCP": {
                        "attack_ip_id": None,
                        "start": None,
                        "end": None,
                    },
                    "UDP": {
                        "attack_ip_id": None,
                        "start": None,
                        "end": None,
                    },
                    "ICMP": {
                        "attack_ip_id": None,
                        "start": None,
                        "end": None,
                    }
                },
                "LANDATTACK": {
                    "TCP": {
                        "attack_ip_id": None,
                    },
                    "UDP": {
                        "attack_ip_id": None,
                    },
                    "ICMP": {
                        "attack_ip_id": None,
                    }
                }
            }

        if attack_type in ("DOS", "PORTSCAN"):
            proto = attack_info[ip][attack_type][attack_proto]
            if proto['start'] is None and ip_list[ip][attack_proto]:
                attack_start_time = datetime.fromtimestamp(
                    ip_list[ip][attack_proto][0]['time']
                    ).strftime("%Y-%m-%d %H:%M:%S")
                proto['start'] = attack_start_time


dos_status = {}         # DoS 공격 상태를 저장
portscan_status = {}    # PortScan 공격 상태를 저장
attack_info = {}        # 공격 정보를 저장

# PortScan/DoS 탐지 함수
def detect_scan_DoS(packet, user_ip):
    global attack_info

    if not packet.haslayer(IP):
        return
    
    ip = packet['IP']

    if ip.src == user_ip and ip.src != ip.dst:
        return
    
    proto_name = get_proto_name(ip.proto)
    # DoS 임계치 설정
    dos_threshold = {
        "TCP": 70,
        "UDP": 70,
        "ICMP": 70
    }
    # PortScan 임계치 설정
    port_scan_threshold = 30
    second = 2

    with lock:
        # ip 별, DoS, PortScan status 초기화
        if ip.src not in dos_status:
            dos_status[ip.src] = {
                "TCP" : {"is_attack": False, "total_count": 0, "last_packet_time": None},
                "UDP" : {"is_attack": False, "total_count": 0, "last_packet_time": None},
                "ICMP" : {"is_attack": False, "total_count": 0, "last_packet_time": None}
            }
        if ip.src not in portscan_status:
            portscan_status[ip.src] = {
                "TCP" : {"is_attack": False, "min_port": None, "max_port": None, "total_count": 0, "last_packet_time": None, 'saved': False},
                "UDP" : {"is_attack": False, "min_port": None, "max_port": None, "total_count": 0, "last_packet_time": None, 'saved': False},
            }

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        
        with lock:
            if dos_status[ip.src]['TCP']['is_attack']:
                dos_status[ip.src]["TCP"]["total_count"] += 1
            if portscan_status[ip.src]['TCP']['is_attack']:
                portscan_status[ip.src]["TCP"]["total_count"] += 1

        with lock:
            # ip_list의 길이를 반환 -> 공격 임계치 검사
            cnt_len = count_packet(ip, packet, "TCP", second)

        if ip.src not in tcp_ports:
            tcp_ports[ip.src] = {
                'ports': {},
                'last_input': datetime.now()
            }

        # slow PortScan을 탐지하기 위한 조건
        if len(tcp_ports[ip.src]['ports']) > 300 or (datetime.now() - tcp_ports[ip.src]['last_input']).seconds >= 30:
            tcp_ports[ip.src]['ports'].clear()
            tcp_ports[ip.src]['last_input'] = datetime.now()

        # ip_list의 패킷 정보를 이용하여 dport 카운트를 구함
        for item in ip_list[ip.src]["TCP"]:
            pkt = item["pkt"]
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                ports = tcp_ports[ip.src]['ports']

                ports[dport] = ports.get(dport, 0) + 1
                tcp_ports[ip.src]['last_input'] = datetime.now()  
        # dport count 특정 포트의 집중도를 나타내며, DoS와 PortScan 공격을 구분하는 데에 쓰임
        tcp_ports_count = len(tcp_ports[ip.src]['ports'])

        # TCP DoS
        if dos_status[ip.src]['TCP']['is_attack'] == False and cnt_len >= dos_threshold[proto_name.upper()] and tcp_ports_count < 3:
            print("DoS Doubt! - TCP\n")
            with lock:
                dos_status[ip.src]['TCP']['last_packet_time'] = datetime.now()
                dos_status[ip.src]['TCP']['is_attack'] = True
                dos_status[ip.src]['TCP']['total_count'] = cnt_len

            dos_flags = copy.deepcopy(ip_list[ip.src])
            
            init_attack_info(ip.src, "DOS", "TCP")
            
            flag_info = return_flag(dos_flags)
            if flag_info is None:
                return
            
            extra = return_tcp_dos(tcp, flag_info)

            common_scan_DoS(ip, proto_name, "DOS", extra)
        
            return
        
        # TCP DoS Attacking 중일 때 시간을 갱신
        with lock:
            if dos_status[ip.src]['TCP']['is_attack'] and cnt_len > dos_threshold['TCP']:
                dos_status[ip.src]['TCP']['last_packet_time'] = datetime.now()

        # DoS 중에는 PortScan 탐지 X
        with lock:
            if dos_status[ip.src]['TCP']['is_attack']:
                return
            
        # TCP PortScan
        if portscan_status[ip.src]['TCP']['is_attack'] == False and cnt_len >= port_scan_threshold and tcp_ports_count >= 10:
            print("Port Scan Doubt! - TCP\n")
            with lock:
                portscan_status[ip.src]['TCP']['saved'] = False
                portscan_status[ip.src]['TCP']['last_packet_time'] = datetime.now()
                portscan_status[ip.src]['TCP']['is_attack'] = True
                portscan_status[ip.src]['TCP']['total_count'] = cnt_len
            
            dos_flags = copy.deepcopy(ip_list[ip.src])
            if tcp_ports[ip.src]['ports']:
                min_port = min(tcp_ports[ip.src]['ports'])
                max_port = max(tcp_ports[ip.src]['ports'])

                portscan_status[ip.src]['TCP']['min_port'] = min_port
                portscan_status[ip.src]['TCP']['max_port'] = max_port

            init_attack_info(ip.src, "PORTSCAN", "TCP")
            
            flag_info = return_flag(dos_flags)
            extra = return_tcp_port_scan(tcp, flag_info)

            common_scan_DoS(ip, proto_name, "PORTSCAN", extra)
                
            return
        
        # TCP PortScan Attacking 중일 때 시간을 갱신
        with lock:
            status = portscan_status[ip.src]['TCP']
            if not status['is_attack']:
                return
            
            ports = tcp_ports[ip.src]['ports']
            if not ports:
                return
           
            current_min = min(ports)
            current_max = max(ports)
        
        now = datetime.now()

        # DoS로 판단되는 경우, port 정보를 저장
        tcp_ports_2s = {}
        for item in ip_list[ip.src]["TCP"]:
            pkt = item["pkt"]
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                tcp_ports_2s[dport] = tcp_ports_2s.get(dport, 0) + 1
        
        if not tcp_ports_2s:
            return
        
        tcp_total = sum(tcp_ports_2s.values())
        tcp_highest_port = max(tcp_ports_2s, key=tcp_ports_2s.get)
        tcp_highest_port_count = tcp_ports_2s[tcp_highest_port]
        tcp_concentrativeness = tcp_highest_port_count / tcp_total

        # 하나의 포트로 임계치 이상이 들어오는 경우, 조건 부합
        if (not dos_status[ip.src]['TCP']['is_attack'] 
            and cnt_len > dos_threshold['TCP'] 
            and tcp_concentrativeness > 0.8
        ):
            print("PortScan -> DoS Doubt!!\n")
            
            end_portscan(ip.src, 'TCP', datetime.now(), force=True)
            with lock:
                portscan_status[ip.src]['TCP']['is_attack'] = False
                dos_status[ip.src]['TCP']['is_attack'] = True
                dos_status[ip.src]['TCP']['last_packet_time'] = now
                dos_status[ip.src]['TCP']['total_count'] = cnt_len
            
            dos_flags = copy.deepcopy(ip_list[ip.src])
            
            init_attack_info(ip.src, "DOS", "TCP")
            
            flag_info = return_flag(dos_flags)
            if flag_info is None:
                return
            
            extra = return_tcp_dos(tcp, flag_info)

            common_scan_DoS(ip, proto_name, "DOS", extra)
        
            return

        with lock:
            status['last_packet_time'] = now

            if status['min_port'] is None:
                status['min_port'] = current_min
            else:
                status['min_port'] = min(status['min_port'], current_min)

            if status['max_port'] is None:
                status['max_port'] = current_max
            else:
                status['max_port'] = max(status['max_port'], current_max)

    # UDP
    if packet.haslayer(UDP):
        udp = packet[UDP]
        
        with lock:
            if dos_status[ip.src]['UDP']['is_attack']:
                dos_status[ip.src]["UDP"]["total_count"] += 1

        with lock:    
            if portscan_status[ip.src]['UDP']['is_attack']:
                portscan_status[ip.src]["UDP"]["total_count"] += 1

        with lock:
            cnt_len = count_packet(ip, packet, "UDP", second)

        if ip.src not in udp_ports:
            udp_ports[ip.src] = {
                'ports': {},
                'last_input': datetime.now()
            }

        if len(udp_ports[ip.src]['ports']) > 300 or (datetime.now() - udp_ports[ip.src]['last_input']).seconds >= 30:
            udp_ports[ip.src]['ports'].clear()
            udp_ports[ip.src]['last_input'] = datetime.now()

        for item in ip_list[ip.src]["UDP"]:
            pkt = item["pkt"]
            if pkt.haslayer(UDP):
                dport = pkt[UDP].dport
                ports = udp_ports[ip.src]['ports']

                ports[dport] = ports.get(dport, 0) + 1
                udp_ports[ip.src]['last_input'] = datetime.now()
        
        udp_ports_count = len(udp_ports[ip.src]['ports'])

        # UDP DoS
        if dos_status[ip.src]['UDP']['is_attack'] == False and cnt_len >= dos_threshold[proto_name.upper()] and udp_ports_count < 3:
            print("DoS Doubt! - UDP\n")
            with lock:
                dos_status[ip.src]['UDP']['last_packet_time'] = datetime.now()
                dos_status[ip.src]['UDP']['is_attack'] = True
                dos_status[ip.src]['UDP']['total_count'] = cnt_len

            init_attack_info(ip.src, "DOS", "UDP")
            
            extra = {
                "sport": udp.sport,
                "sport_name": get_port_name(udp.sport),
                "dport": udp.dport,
                "dport_name": get_port_name(udp.dport),
            }

            common_scan_DoS(ip, proto_name, "DOS", extra)
        
            return
        
        # UDP DoS Attacking 중일 때 시간을 갱신
        with lock:
            if dos_status[ip.src]['UDP']['is_attack']:
                dos_status[ip.src]['UDP']['last_packet_time'] = datetime.now()

        # DoS 중에는 PortScan 탐지 X
        with lock:
            if dos_status[ip.src]['UDP']['is_attack']:
                return
            
        # UDP PortScan
        if portscan_status[ip.src]['UDP']['is_attack'] == False and cnt_len >= port_scan_threshold and udp_ports_count >= 10:
            print("Port Scan Doubt! - UDP\n")
            with lock:
                portscan_status[ip.src]['UDP']['saved'] = False
                portscan_status[ip.src]['UDP']['last_packet_time'] = datetime.now()
                portscan_status[ip.src]['UDP']['is_attack'] = True
                portscan_status[ip.src]['UDP']['total_count'] = cnt_len

            if udp_ports[ip.src]['ports']:
                min_port = min(udp_ports[ip.src]['ports'])
                max_port = max(udp_ports[ip.src]['ports'])

                portscan_status[ip.src]['UDP']['min_port'] = min_port
                portscan_status[ip.src]['UDP']['max_port'] = max_port

            init_attack_info(ip.src, "PORTSCAN", "UDP")
            
            extra = {
                "sport": udp.sport,
                "sport_name": get_port_name(udp.sport),
                "dport": udp.dport,
                "dport_name": get_port_name(udp.dport),
            }

            common_scan_DoS(ip, proto_name, "PORTSCAN", extra)
                
            return
        
        # UDP PortScan Attacking 중일 때 시간을 갱신
        with lock:
            status = portscan_status[ip.src]['UDP']
            if not status['is_attack']:
                return
            
            ports = udp_ports[ip.src]['ports']
            if not ports:
                return
           
            current_min = min(ports)
            current_max = max(ports)
        
        now = datetime.now()

        udp_ports_2s = {}
        for item in ip_list[ip.src]["UDP"]:
            pkt = item["pkt"]
            if pkt.haslayer(UDP):
                dport = pkt[UDP].dport
                udp_ports_2s[dport] = udp_ports_2s.get(dport, 0) + 1
        
        if not udp_ports_2s:
            return
        
        udp_total = sum(udp_ports_2s.values())
        udp_highest_port = max(udp_ports_2s, key=udp_ports_2s.get)
        udp_highest_port_count = udp_ports_2s[udp_highest_port]
        udp_concentrativeness = udp_highest_port_count / udp_total

        if (not dos_status[ip.src]['UDP']['is_attack'] 
            and cnt_len > dos_threshold['UDP'] 
            and udp_concentrativeness > 0.8
        ):
            print("UDP - PortScan -> DoS Doubt!!\n")
            
            end_portscan(ip.src, 'UDP', datetime.now(), force=True)
            with lock:
                portscan_status[ip.src]['UDP']['is_attack'] = False
                dos_status[ip.src]['UDP']['is_attack'] = True
                dos_status[ip.src]['UDP']['last_packet_time'] = now
                dos_status[ip.src]['UDP']['total_count'] = cnt_len
            
            init_attack_info(ip.src, "DOS", "UDP")
            
            extra = {
                "sport": udp.sport,
                "sport_name": get_port_name(udp.sport),
                "dport": udp.dport,
                "dport_name": get_port_name(udp.dport),
            }

            common_scan_DoS(ip, proto_name, "DOS", extra)
        
            return

        with lock:
            status['last_packet_time'] = now

            if status['min_port'] is None:
                status['min_port'] = current_min
            else:
                status['min_port'] = min(status['min_port'], current_min)

            if status['max_port'] is None:
                status['max_port'] = current_max
            else:
                status['max_port'] = max(status['max_port'], current_max)

    # ICMP 
    if packet.haslayer(ICMP):
        with lock:
            if dos_status[ip.src]['ICMP']['is_attack']:
                dos_status[ip.src]["ICMP"]["total_count"] += 1
        
        with lock:
            cnt_len = count_packet(ip, packet, "ICMP", second)

        # ICMP DoS
        if dos_status[ip.src]['ICMP']['is_attack'] == False and cnt_len >= dos_threshold[proto_name.upper()]:
            print("DoS Doubt! - ICMP\n")
            with lock:
                dos_status[ip.src]['ICMP']['last_packet_time'] = datetime.now()
                dos_status[ip.src]['ICMP']['is_attack'] = True
                dos_status[ip.src]['ICMP']['total_count'] = cnt_len

            init_attack_info(ip.src, "DOS", "ICMP")

            # Counter를 이용하여 패킷의 Type과 Code의 빈도를 계산
            counter = Counter()
            for item in ip_list[ip.src]["ICMP"]:
                pkt = item['pkt']
                if pkt.haslayer(ICMP):
                    counter[(pkt[ICMP].type, pkt[ICMP].code)] += 1
            if counter:
                (int_icmp_type, int_icmp_code), freq = counter.most_common(1)[0]
            else:
                print("ICMP Counter NOT Exist!\n")
                int_icmp_type, int_icmp_code, freq = None, None, 0
            icmp_type, icmp_code = get_icmp_info(int_icmp_type, int_icmp_code)

            extra = {
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
                "frequency_rate": f'{round((freq / cnt_len * 100))}%'
            }
            common_scan_DoS(ip, proto_name, "DOS", extra)

            return

        # ICMP DoS Attacking 중일 때 시간을 갱신
        with lock:
            if dos_status[ip.src]['ICMP']['is_attack']:
                dos_status[ip.src]['ICMP']['last_packet_time'] = datetime.now()
        
        # DoS 중에는 PortScan 탐지 X
        with lock:
            if dos_status[ip.src]['ICMP']['is_attack']:
                return

# ---------------------------------

# 패킷 캡처 옵션 설정 및 실행 함수
def sniffing(filter, user_ip):
    sniff(filter=filter, prn=lambda pkt: detect_attack(pkt, user_ip), count=0)

# 파일이 제일 처음 실행하는 부분
if __name__ == '__main__':
    filter='ip'
    user_ip = get_user_ip()
    threading.Thread(target=dos_end_timer, daemon=True).start()
    threading.Thread(target=portscan_end_timer, daemon=True).start()
    sniffing(filter, user_ip)
