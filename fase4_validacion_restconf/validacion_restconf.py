import requests
import json
import yaml
import datetime
import socket
import urllib3

# Desactivar advertencias de certificados SSL autofirmados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 1. Metadatos de auditoria
print("=== VALIDACION RESTCONF ===")
print("Script : validacion_restconf.py")
print(f"Fecha  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Host   : {socket.gethostname()}")
print("===========================\n")

# 2. Cargar variables
with open("../vars/vars_005D-15.yaml") as f:
    vars_data = yaml.safe_load(f)

base_url = f"https://{vars_data['router']['ip']}/restconf/data"
headers = {"Accept": "application/yang-data+json"}
auth = (vars_data['router']['usuario'], vars_data['router']['password'])

# 3. Definir los Endpoints a consultar
endpoints = {
    "hostname": ("/Cisco-IOS-XE-native:native/hostname", "get_hostname.json"),
    "loopback": (f"/ietf-interfaces:interfaces/interface=Loopback{vars_data['router']['loopback_id']}", "get_loopback.json"),
    "interfaces": ("/ietf-interfaces:interfaces/interface=GigabitEthernet1", "get_interfaces.json"),
    "ntp": ("/Cisco-IOS-XE-native:native/ntp", "get_ntp.json")
}

resultados = {}

# 4. Ejecutar consultas y guardar JSON
print("Consultando API RESTCONF...\n")
for key, (path, filename) in endpoints.items():
    url = base_url + path
    resp = requests.get(url, headers=headers, auth=auth, verify=False)
    
    if resp.status_code == 200:
        data = resp.json()
        with open(f"evidencias/responses/{filename}", "w") as out_file:
            json.dump(data, out_file, indent=4)
        resultados[key] = data
    else:
        resultados[key] = {}

# --- HELPER PARA LEER JSON (Lista vs Diccionario) ---
def get_iface_data(data):
    iface = data.get('ietf-interfaces:interface', {})
    return iface[0] if isinstance(iface, list) else iface

# 5. Extraccion segura de los datos JSON
try: 
    host_json = resultados['hostname'].get('Cisco-IOS-XE-native:hostname', "N/A")
except: 
    host_json = "N/A"

try:
    iface_loop = get_iface_data(resultados['loopback'])
    addr_data = iface_loop.get('ietf-ip:ipv4', {}).get('address', [{}])
    addr_dict = addr_data[0] if isinstance(addr_data, list) else addr_data
    
    loop_ip_json = addr_dict.get('ip', "N/A")
    loop_mask_json = addr_dict.get('netmask', "N/A")
except:
    loop_ip_json = "N/A"
    loop_mask_json = "N/A"

try:
    iface_wan = get_iface_data(resultados['interfaces'])
    desc_wan_json = iface_wan.get('description', "N/A")
except: 
    desc_wan_json = "N/A"

try:
    # CORRECCION DEFINITIVA NTP
    ntp_server_obj = resultados['ntp'].get('Cisco-IOS-XE-native:ntp', {}).get('server', {})
    
    if isinstance(ntp_server_obj, list) and len(ntp_server_obj) > 0:
        ntp_json = ntp_server_obj[0].get('ip-address', "N/A")
    elif isinstance(ntp_server_obj, dict):
        if 'server-list' in ntp_server_obj:
            ntp_json = ntp_server_obj['server-list'][0].get('ip-address', "N/A")
        elif 'peer-list' in ntp_server_obj:
            ntp_json = ntp_server_obj['peer-list'][0].get('ip-address', "N/A")
        else:
            ntp_json = ntp_server_obj.get('ip-address', "N/A")
    else:
        ntp_json = "N/A"
except:
    ntp_json = "N/A"

# 6. Comparar e imprimir resultados
print("Resultados de la Auditoria:")
criterios_ok = 0

def evaluar(nombre, esperado, actual):
    global criterios_ok
    if str(esperado) == str(actual):
        print(f"[OK] {nombre}: {actual}")
        criterios_ok += 1
    else:
        print(f"[FAIL] {nombre}: Esperado '{esperado}' | Encontrado '{actual}'")

evaluar("Hostname", vars_data['cliente']['hostname'], host_json)
evaluar("IP Loopback", vars_data['router']['loopback_ip'], loop_ip_json)
evaluar("Mascara Loopback", vars_data['router']['loopback_mask'], loop_mask_json)
evaluar("Descripcion WAN", vars_data['router']['descripcion_wan'], desc_wan_json)
evaluar("Servidor NTP", vars_data['router']['ntp_server'], ntp_json)

print("\n--------------------------")
if criterios_ok == 5:
    print("RESULTADO GLOBAL: CONFORME")
else:
    print("RESULTADO GLOBAL: NO CONFORME")
print("--------------------------")
