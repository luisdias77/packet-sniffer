from scapy.all import sniff
import analise

def iniciar_captura(interface, modo, filtro = ""):
    print(f"[Captura] Motor iniciado na interface '{interface}' com filtro: {filtro}'...")
    print("[Captura] A escutar a rede... (Pressiona Ctrl+C para parar)\n")
    
    callback_com_modo = lambda pkt: analise.processar_pacote(pkt, modo)

    # O Scapy vai chamar a função 'processar_pacote' do analise.py para cada pacote apanhado.
    # Se a interface for "todas", não filtramos por placa de rede.
    if interface.lower() == "todas":
        sniff(prn=callback_com_modo, filter = filtro, store=False)
    else:
        sniff(iface=interface, prn=callback_com_modo, filter = filtro, store=False)
