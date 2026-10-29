# import log
# from scapy.all import Ether, IP, IPv6, ARP, TCP, UDP, ICMP, DNS, DHCP
# from datetime import datetime

# def processar_pacote(pacote, modo):

#     # Extrair as informações relevantes do pacote usando Scapy
#     tempo_captura = datetime.fromtimestamp(float(pacote.time)).strftime('%Y-%m-%d %H:%M:%S')
#     tamanho = len(pacote)
#     resumo = pacote.summary()


#     # Saber qual a interface de onde veio o pacote, em que o Scapy guarda isso no campo "sniffed_on", o objeto do pacote tem um campo chamado "sniffed_on" que indica a interface de onde o pacote foi capturado. 
#     interface = pacote.sniffed_on if pacote.sniffed_on else "eth0"  # Valor padrão caso não esteja presente
    
#     # Valores por defeito para os endereços
#     mac_origem = pacote[Ether].src if pacote.haslayer(Ether) else "N/A" # Se não tiver camada Ethernet, coloca "N/A"
#     mac_destino = pacote[Ether].dst if pacote.haslayer(Ether) else "N/A" # Se não tiver camada Ethernet, coloca "N/A"

#     # Valores iniciais para os endereços IP
#     ip_origem = "N/A"
#     ip_destino = "N/A"
    
#     if pacote.haslayer(IP): # Se tiver camada IP
#         ip_origem = pacote[IP].src
#         ip_destino = pacote[IP].dst
#     elif pacote.haslayer(IPv6): # Se tiver camada IPv6
#         ip_origem = pacote[IPv6].src
#         ip_destino = pacote[IPv6].dst

#     # PROTOCOLOS -------------------------------------------------------------------------------------------------------
#     protocolo = "Outro"
    
#     # ARP
#     if pacote.haslayer(ARP):
#         protocolo = "ARP"
#         ip_origem = pacote[ARP].psrc
#         ip_destino = pacote[ARP].pdst
#         resumo = f"ARP {'Request' if pacote[ARP].op == 1 else 'Reply'}"

#     # IP
#     elif pacote.haslayer(IP) or pacote.haslayer(IPv6):

#         if pacote.haslayer(ICMP):
#             protocolo = "ICMP"
#             resumo = f"ICMP Type: {pacote[ICMP].type} Code: {pacote[ICMP].code}"

#         elif pacote.haslayer(UDP):
#              protocolo = "UDP"

#              if pacote.haslayer(DNS) and pacote[DNS].qd:
#                 protocolo = "DNS"
#                 nome_pesquisado = pacote[DNS].qd.qname.decode('utf-8', errors='ignore')
#                 resumo = f"DNS Query: {nome_pesquisado}"

#              elif pacote.haslayer(DHCP):
#                 protocolo = "DHCP"
#                 tipo_msg = "Mensagem DHCP"
#                 for opt in pacote[DHCP].options:
#                     if opt[0] == 'message-type':
#                         tipos = {1: 'Discover', 2: 'Offer', 3: 'Request', 5: 'ACK'}
#                         tipo_msg = f"DHCP {tipos.get(opt[1], 'Outro')}"
#                         break
#                 resumo = tipo_msg

#              else: resumo = f"UDP Src Port: {pacote[UDP].sport} -> Dst Port: {pacote[UDP].dport}"
        

#         elif pacote.haslayer(TCP):
#              protocolo = "TCP"
#              flags = pacote[TCP].flags

#              if flags == "S":
#                 fase = "[SYN] Pedido de Ligação"
#              elif flags == "SA":
#                 fase = "[SYN-ACK] Aceite"
#              elif flags == "A":
#                 fase = "[ACK] Confirmação"
#              elif flags == "F" or flags == "FA":
#                 fase = "[FIN] Terminação"
#              elif flags == "PA":
#                 fase = "[PSH-ACK] Dados/Resposta"
#              else:
#                 fase = f"Flags [{flags}]"
                
#              resumo = f"TCP {fase} | Port: {pacote[TCP].sport} -> {pacote[TCP].dport}"

#         else: 
#             protocolo = pacote[IP].proto  # Se for IP mas não for TCP/UDP/ICMP, mostra o número do protocolo IP
#             proto_num = pacote[IP].proto if pacote.haslayer(IP) else pacote[IPv6].nh
#             protocolo = f"IP Proto ({proto_num})"
#             resumo = "Outro tráfego IP/IPv6"
    

#     # Organizar todos os dados para enviar para o ficheiro de log ou para imprimir na consola
#     dados_organizados = {
        
#         "timestamp": tempo_captura,
#         "interface": interface,
#         "protocolo": protocolo,
#         "mac_origem": mac_origem,
#         "mac_destino": mac_destino,
#         "ip_origem": ip_origem,
#         "ip_destino": ip_destino,
#         "tamanho": tamanho,
#         "resumo": resumo
    
#     }
    
#     # Enviar para o log, que irá decidir o que fazer com os dados, dependendo do modo selecionado pelo utilizador (live, log, ambos)
#     log.registar_pacote(dados_organizados, modo)


import log
from scapy.all import Ether, IP, IPv6, ARP, TCP, UDP, ICMP, DNS, DHCP, Dot11
from datetime import datetime

def processar_pacote(pacote, modo):
    tempo_captura = datetime.fromtimestamp(float(pacote.time)).strftime('%Y-%m-%d %H:%M:%S')
    tamanho = len(pacote)
    
    interface = pacote.sniffed_on if pacote.sniffed_on else "eth0"

    # Aqui faz-se a distinção entre 802.11 (Wi-Fi) e Ethernet
    # Se o pacote tiver camada Dot11, é Wi-Fi, caso contrário é Ethernet
    if pacote.haslayer(Dot11):
        protocolo = "802.11 (Wi-Fi)"
        mac_origem = pacote[Dot11].addr2 if pacote[Dot11].addr2 else "N/A"
        mac_destino = pacote[Dot11].addr1 if pacote[Dot11].addr1 else "N/A"
        resumo_wifi = ""
    
    else:
        mac_origem = pacote[Ether].src if pacote.haslayer(Ether) else "N/A"
        mac_destino = pacote[Ether].dst if pacote.haslayer(Ether) else "N/A"

    ip_origem = "N/A"
    ip_destino = "N/A"
    info_rede = "" # campo TTL - Time To Live
    
    # Se o pacote tem o cabeçalho ipv4
    if pacote.haslayer(IP):
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst
        info_rede = f"TTL: {pacote[IP].ttl}"

    elif pacote.haslayer(IPv6):
        ip_origem = pacote[IPv6].src
        ip_destino = pacote[IPv6].dst
        info_rede = f"Hop Limit: {pacote[IPv6].hlim}"

    protocolo = "Outro"
    resumo = ""

    if pacote.haslayer(ARP):
        protocolo = "ARP"
        ip_origem = pacote[ARP].psrc
        ip_destino = pacote[ARP].pdst
        resumo = f"ARP {'Request' if pacote[ARP].op == 1 else 'Reply'}"

    elif pacote.haslayer(IP) or pacote.haslayer(IPv6):
        if pacote.haslayer(ICMP):
            protocolo = "ICMP"
            resumo = f"ICMP Type: {pacote[ICMP].type} Code: {pacote[ICMP].code}"

        elif pacote.haslayer(UDP):
             protocolo = "UDP"
             if pacote.haslayer(DNS) and pacote[DNS].qd:
                protocolo = "DNS"
                nome_pesquisado = pacote[DNS].qd.qname.decode('utf-8', errors='ignore')
                resumo = f"DNS Query: {nome_pesquisado}"
             elif pacote.haslayer(DHCP):
                protocolo = "DHCP"
                resumo = "Mensagem DHCP"
             else: 
                resumo = f"UDP Port: {pacote[UDP].sport} -> {pacote[UDP].dport}"

        elif pacote.haslayer(TCP):
             protocolo = "TCP"
             resumo = f"TCP Flags: {pacote[TCP].flags} | Port: {pacote[TCP].sport} -> {pacote[TCP].dport}"

        resumo = f"{info_rede} | {resumo}" if resumo else info_rede

    dados_organizados = {
        "timestamp": tempo_captura,
        "interface": interface,
        "protocolo": protocolo,
        "mac_origem": mac_origem,
        "mac_destino": mac_destino,
        "ip_origem": ip_origem,
        "ip_destino": ip_destino,
        "tamanho": tamanho,
        "resumo": resumo
    }
    
    log.registar_pacote(dados_organizados, modo)