import yaml
from ncclient import manager
import xml.dom.minidom
import xml.etree.ElementTree as ET
import datetime
import socket

# 1. Metadatos de auditoria (Exigencia de la rubrica)
print("=== VALIDACION NETCONF ===")
print("Script : validacion_netconf.py")
print(f"Fecha  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Host   : {socket.gethostname()}")
print("==========================\n")

# 2. Cargar tu archivo de variables centralizado
with open("../vars/vars_005D-15.yaml") as f:
    vars_data = yaml.safe_load(f)

# 3. Conexion NETCONF (allow_agent y look_for_keys en False segun rubrica)
print("Conectando al router via NETCONF por puerto 830...")
m = manager.connect(
    host=vars_data['router']['ip'],
    port=830,
    username=vars_data['router']['usuario'],
    password=vars_data['router']['password'],
    hostkey_verify=False,
    look_for_keys=False,
    allow_agent=False
)

# 4. Capturar configuracion con Filtro XML para IOS-XE native
netconf_filter = """
<filter>
  <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native"/>
</filter>
"""
respuesta = m.get_config('running', netconf_filter)
xml_crudo = respuesta.xml

# 5. Guardar XML crudo en la carpeta de evidencias
xml_formateado = xml.dom.minidom.parseString(xml_crudo).toprettyxml()
with open("evidencias/rpc_reply_raw.xml", "w") as f:
    f.write(xml_formateado)

# 6. Parsear XML (Limpiamos los namespaces para que la busqueda no falle)
root = ET.fromstring(xml_crudo)
for elem in root.iter():
    if '}' in elem.tag:
        elem.tag = elem.tag.split('}', 1)[1]

# 7. Extraer los 5 valores exigidos del arbol XML
host_xml = root.find('.//hostname').text if root.find('.//hostname') is not None else "N/A"

desc_wan_xml = "N/A"
for intf in root.findall('.//GigabitEthernet'):
    if intf.find('name') is not None and intf.find('name').text == '1':
        if intf.find('description') is not None:
            desc_wan_xml = intf.find('description').text

loop_ip_xml = "N/A"
loop_mask_xml = "N/A"
for intf in root.findall('.//Loopback'):
    if intf.find('name') is not None and intf.find('name').text == str(vars_data['router']['loopback_id']):
        if intf.find('.//primary/address') is not None:
            loop_ip_xml = intf.find('.//primary/address').text
        if intf.find('.//primary/mask') is not None:
            loop_mask_xml = intf.find('.//primary/mask').text

ntp_xml = root.find('.//ntp//ip-address').text if root.find('.//ntp//ip-address') is not None else "N/A"

# 8. Comparar contra tus variables e imprimir resultados
print("\nResultados de la Auditoria:")
criterios_ok = 0

def evaluar(nombre, esperado, actual):
    global criterios_ok
    if str(esperado) == str(actual):
        print(f"[OK] {nombre}: {actual}")
        criterios_ok += 1
    else:
        print(f"[FAIL] {nombre}: Esperado '{esperado}' | Encontrado '{actual}'")

evaluar("Hostname", vars_data['cliente']['hostname'], host_xml)
evaluar("IP Loopback", vars_data['router']['loopback_ip'], loop_ip_xml)
evaluar("Mascara Loopback", vars_data['router']['loopback_mask'], loop_mask_xml)
evaluar("Descripcion WAN", vars_data['router']['descripcion_wan'], desc_wan_xml)
evaluar("Servidor NTP", vars_data['router']['ntp_server'], ntp_xml)

print("\n--------------------------")
if criterios_ok == 5:
    print("RESULTADO GLOBAL: CONFORME")
else:
    print("RESULTADO GLOBAL: NO CONFORME")
print("--------------------------")
